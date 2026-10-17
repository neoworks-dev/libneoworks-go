#include "client.hpp"
#include "files.hpp"
#include "query_fields.hpp"
#include "references.hpp"

namespace nw {

namespace {

// A string is indexed as it is, a File by its name.
void addSearchText(const Json& value, std::vector<std::string>& texts) {
  if (value.is_string()) {
    texts.push_back(lowercaseAscii(value.get<std::string>()));
    return;
  }
  if (value.is_object() && value.contains("name") && value.at("name").is_string()) {
    texts.push_back(lowercaseAscii(value.at("name").get<std::string>()));
  }
}

void collectSearchTexts(const Json& value, std::vector<std::string>& texts) {
  if (!value.is_array()) {
    addSearchText(value, texts);
    return;
  }
  for (const Json& element : value) {
    addSearchText(element, texts);
  }
}

std::vector<std::string> searchTextsOf(const TableDescriptor& descriptor, const Json& content) {
  std::vector<std::string> texts;
  for (uint32_t ordinal : descriptor.searchable) {
    const FieldDescriptor* field = descriptor.model->fieldByOrdinal(ordinal);
    auto value = content.find(field->name);
    if (value != content.end()) {
      collectSearchTexts(*value, texts);
    }
  }
  return texts;
}

// `content` as an app sees it: Files without keys and references as ids.
IndexedNode indexedNodeOf(const TableDescriptor& descriptor, const Json& content) {
  IndexedNode entry;
  entry.table = descriptor.modelName;
  entry.values = fieldValuesOf(*descriptor.model, content);
  entry.searchTexts = searchTextsOf(descriptor, content);
  for (const ContentReference& reference : collectReferences(*descriptor.model, content)) {
    entry.references.push_back(IndexedReference{reference.fieldOrdinal, reference.rowId});
  }
  return entry;
}

bool isAddressedTo(const AccessGrant& grant, const std::string& principalType, const std::string& principalId) {
  return grant.principalType == principalType && grant.principalId == principalId;
}

}  // namespace

void Client::attachIndex() {
  unindexedNodeIds_.clear();
  for (const std::string& nodeId : database_->allNodeIds()) {
    unindexedNodeIds_.insert(nodeId);
  }
  database_->setNodeObserver([this](const std::string& nodeId) { onNodeChanged(nodeId); });
  database_->setGrantObserver([this](const std::string& nodeId) { onGrantChanged(nodeId); });
}

void Client::onNodeChanged(const std::string& nodeId) {
  indexNode(nodeId);
  indexDependentsOf(nodeId);
}

// A row that became readable unlocks the pending rows belonging to it and the rows it links to.
void Client::indexDependentsOf(const std::string& nodeId) {
  std::vector<std::string> unlocked{nodeId};
  while (!unlocked.empty()) {
    std::string unlockedId = unlocked.back();
    unlocked.pop_back();
    for (const std::string& dependentId : dependentsOf(unlockedId)) {
      if (unindexedNodeIds_.count(dependentId) == 0) {
        continue;
      }
      indexNode(dependentId);
      if (unindexedNodeIds_.count(dependentId) == 0) {
        unlocked.push_back(dependentId);
      }
    }
  }
}

std::vector<std::string> Client::dependentsOf(const std::string& nodeId) const {
  std::vector<std::string> dependents = database_->childrenOf(nodeId);
  const Node* node = database_->findNode(nodeId);
  if (node != nullptr) {
    dependents.insert(dependents.end(), node->links.begin(), node->links.end());
  }
  return dependents;
}

void Client::onGrantChanged(const std::string& nodeId) {
  if (hasRevokedOwnGrant(nodeId)) {
    ownGrantRevoked_ = true;
  }
}

bool Client::hasRevokedOwnGrant(const std::string& nodeId) const {
  for (const AccessGrant& grant : database_->grantsForNode(nodeId)) {
    if (isAddressedTo(grant, signer_.authorType, signer_.authorId) && grant.revokedAt.has_value()) {
      return true;
    }
  }
  return false;
}

Result<IndexedNode> Client::indexEntryFor(const Node& node) {
  Result<StoredContent> stored = readStoredContent(node, nullptr);
  if (!stored.ok()) {
    return stored.status();
  }
  const TableDescriptor& table = *stored.value().table;
  Json& content = stored.value().content;
  removeFileKeys(*table.model, content);
  removeReferenceKeys(*table.model, content);
  return indexedNodeOf(table, content);
}

// A node that cannot be read yet stays pending and is tried again once keys, grants,
// ancestors or the collection's descriptor arrive.
void Client::indexNode(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted || isRoot(*node)) {
    index_.erase(nodeId);
    unindexedNodeIds_.erase(nodeId);
    return;
  }
  CodecError callerError = lastContentError_;
  Result<IndexedNode> entry = indexEntryFor(*node);
  lastContentError_ = callerError;
  if (entry.ok()) {
    index_.put(node->collection, nodeId, entry.take());
    unindexedNodeIds_.erase(nodeId);
    return;
  }
  index_.erase(nodeId);
  if (entry.status() == Status::IntegrityFailure) {
    unindexedNodeIds_.erase(nodeId);
    return;
  }
  unindexedNodeIds_.insert(nodeId);
}

void Client::indexPendingNodes() {
  std::vector<std::string> pending(unindexedNodeIds_.begin(), unindexedNodeIds_.end());
  for (const std::string& nodeId : pending) {
    indexNode(nodeId);
  }
}

void Client::resetIndexOf(const std::string& collection) {
  index_.eraseCollection(collection);
  for (const std::string& nodeId : database_->nodesInCollection(collection)) {
    unindexedNodeIds_.insert(nodeId);
  }
}

// Every row reached from this holder's active grants: a whole-row grant reaches the rows belonging
// to the row and the rows it links to, a grant on some facets only the row itself.
std::set<std::string> Client::rowsInReach() const {
  std::set<std::string> reached;
  std::vector<std::string> queue;
  for (const AccessGrant& grant : database_->allGrants()) {
    bool active = isAddressedTo(grant, signer_.authorType, signer_.authorId) && !grant.revokedAt.has_value();
    if (active && grant.facets.has_value()) {
      reached.insert(grant.nodeId);
    }
    if (active && !grant.facets.has_value()) {
      queue.push_back(grant.nodeId);
    }
  }
  std::set<std::string> expanded;
  while (!queue.empty()) {
    std::string nodeId = queue.back();
    queue.pop_back();
    if (!expanded.insert(nodeId).second) {
      continue;
    }
    reached.insert(nodeId);
    std::vector<std::string> children = database_->childrenOf(nodeId);
    queue.insert(queue.end(), children.begin(), children.end());
    const Node* node = database_->findNode(nodeId);
    if (node != nullptr) {
      queue.insert(queue.end(), node->links.begin(), node->links.end());
    }
  }
  return reached;
}

void Client::removeRowsOutOfReach() {
  if (!ownGrantRevoked_) {
    return;
  }
  ownGrantRevoked_ = false;
  std::set<std::string> reached = rowsInReach();
  for (const std::string& nodeId : database_->allNodeIds()) {
    const LocalNode* local = database_->findLocal(nodeId);
    if (reached.count(nodeId) > 0 || local->dirty) {
      continue;
    }
    keyring_.forgetNode(nodeId);
    database_->removeNode(nodeId);
  }
}

}  // namespace nw
