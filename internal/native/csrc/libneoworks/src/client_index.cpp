#include "client.hpp"
#include "query_fields.hpp"
#include "references.hpp"

namespace nw {

namespace {

constexpr int kMaxAncestorWalk = 64;

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

std::vector<std::string> searchTextsOf(const NodeDescriptor& descriptor, const Json& content) {
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

IndexedNode indexedNodeOf(const Node& node, const NodeDescriptor& descriptor, const Json& content) {
  IndexedNode entry;
  entry.kind = node.kind;
  entry.parentId = node.parentId;
  entry.values = fieldValuesOf(*descriptor.model, content);
  entry.searchTexts = searchTextsOf(descriptor, content);
  for (const ContentReference& reference : collectReferences(*descriptor.model, content)) {
    entry.references.push_back(IndexedReference{reference.fieldOrdinal, reference.nodeId});
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
  const Node* node = database_->findNode(nodeId);
  if (node != nullptr && node->kind != "item") {
    indexPendingNodes();
  }
}

// Revoked grants are the only change that takes nodes out of view without touching the nodes.
void Client::onGrantChanged(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr) {
    return;
  }
  if (ownGrantsOn(nodeId) == OwnGrants::Revoked) {
    evictNodesOutOfView(node->collection);
  }
}

// Whether this holder has an unrevoked grant on the node itself, only revoked ones, or none.
Client::OwnGrants Client::ownGrantsOn(const std::string& nodeId) const {
  OwnGrants state = OwnGrants::None;
  for (const AccessGrant& grant : database_->grantsForNode(nodeId)) {
    if (!isAddressedTo(grant, signer_.authorType, signer_.authorId)) {
      continue;
    }
    if (!grant.revokedAt.has_value()) {
      return OwnGrants::Active;
    }
    state = OwnGrants::Revoked;
  }
  return state;
}

bool Client::holderLostView(const Node& node) const {
  bool sawRevokedGrant = false;
  const Node* cursor = &node;
  for (int step = 0; step < kMaxAncestorWalk && cursor != nullptr; ++step) {
    OwnGrants grants = ownGrantsOn(cursor->id);
    if (grants == OwnGrants::Active) {
      return false;
    }
    sawRevokedGrant = sawRevokedGrant || grants == OwnGrants::Revoked;
    if (!cursor->parentId.has_value()) {
      break;
    }
    cursor = database_->findNode(*cursor->parentId);
  }
  return sawRevokedGrant && effectiveRole(node.id).empty();
}

void Client::evictNodesOutOfView(const std::string& collection) {
  std::vector<std::string> lost;
  for (const auto& [nodeId, entry] : index_.nodesOf(collection)) {
    const Node* node = database_->findNode(nodeId);
    if (node != nullptr && holderLostView(*node)) {
      lost.push_back(nodeId);
    }
  }
  for (const std::string& nodeId : lost) {
    index_.erase(nodeId);
    unindexedNodeIds_.erase(nodeId);
  }
}

Result<IndexedNode> Client::indexEntryFor(const Node& node) {
  if (node.kind == "root") {
    IndexedNode root;
    root.kind = node.kind;
    return root;
  }
  if (holderLostView(node)) {
    return Status::Forbidden;
  }
  const SchemaDescriptor* schema = descriptorFor(node.collection);
  const NodeDescriptor* descriptor = nullptr;
  if (schema != nullptr) {
    descriptor = schema->nodeByKind(node.kind);
  }
  if (descriptor == nullptr) {
    return Status::InvalidState;
  }
  Result<Json> content = readContent(node, nullptr);
  if (!content.ok()) {
    return content.status();
  }
  return indexedNodeOf(node, *descriptor, content.value());
}

// A node that cannot be read yet stays pending and is tried again once keys, grants,
// ancestors or the collection's descriptor arrive.
void Client::indexNode(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted || isShortcut(*node)) {
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
  if (entry.status() == Status::Forbidden || entry.status() == Status::IntegrityFailure) {
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

}  // namespace nw
