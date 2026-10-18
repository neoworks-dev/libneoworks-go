#include "client.hpp"
#include "files.hpp"
#include "query_fields.hpp"
#include "references.hpp"

namespace nw {

namespace {

// `content` as an app sees it: Files without keys and references as ids.
IndexedNode indexedNodeOf(const TableDescriptor& descriptor, const Json& content) {
  IndexedNode entry;
  entry.table = descriptor.modelName;
  entry.fields = indexedMessageOf(*descriptor.model, content);
  for (const ContentReference& reference : collectReferences(*descriptor.model, content)) {
    entry.references.push_back(IndexedReference{reference.fieldOrdinal, reference.rowId});
  }
  return entry;
}

}  // namespace

void Client::attachIndex() {
  unindexedNodeIds_.clear();
  awaitingMigratedIndexIds_.clear();
  for (const std::string& nodeId : database_->allNodeIds()) {
    unindexedNodeIds_.insert(nodeId);
  }
  database_->setNodeObserver([this](const std::string& nodeId) { onNodeChanged(nodeId); });
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

// Also makes the table's sorted indexes exist, so that putting the entry places the row in them.
// Unsupported: the row was written at a version whose field ordinals the registered descriptor and
// its queries do not share. Such a row is indexed from migrated content, see indexMigrated.
Result<IndexedNode> Client::indexEntryFor(const Node& node) {
  if (!sharesFieldsWithRegistered(node)) {
    return Status::Unsupported;
  }
  Result<StoredContent> stored = readStoredContent(node, nullptr);
  if (!stored.ok()) {
    return stored.status();
  }
  const TableDescriptor& table = *stored.value().table;
  Result<const TableDescriptor*> registeredTable = tableDescriptorFor(node.collection, table.modelName);
  if (!registeredTable.ok()) {
    return registeredTable.status();
  }
  index_.defineIndexes(node.collection, table.modelName, registeredTable.value()->indexes);
  Json& content = stored.value().content;
  removeFileKeys(*table.model, content);
  removeReferenceKeys(*table.model, content);
  return indexedNodeOf(table, content);
}

// A node that cannot be read yet stays pending and is tried again once keys, grants,
// ancestors or the collection's descriptor arrive.
void Client::indexNode(const std::string& nodeId) {
  awaitingMigratedIndexIds_.erase(nodeId);
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted || isRoot(*node)) {
    index_.erase(nodeId);
    unindexedNodeIds_.erase(nodeId);
    return;
  }
  CodecError callerError = lastContentError_;
  if (isOnEarlierLine(*node)) {
    awaitMigratedIndex(*node);
    lastContentError_ = callerError;
    return;
  }
  Result<IndexedNode> entry = indexEntryFor(*node);
  lastContentError_ = callerError;
  if (entry.ok()) {
    index_.put(node->collection, nodeId, entry.take());
    unindexedNodeIds_.erase(nodeId);
    return;
  }
  index_.erase(nodeId);
  if (entry.status() == Status::IntegrityFailure || entry.status() == Status::Unsupported) {
    unindexedNodeIds_.erase(nodeId);
    return;
  }
  unindexedNodeIds_.insert(nodeId);
}

// The entry is made by indexMigrated; until then the row is out of the index.
void Client::awaitMigratedIndex(const Node& node) {
  index_.erase(node.id);
  Result<StoredContent> readable = readStoredContent(node, nullptr);
  if (readable.ok()) {
    awaitingMigratedIndexIds_.insert(node.id);
    unindexedNodeIds_.erase(node.id);
    return;
  }
  if (readable.status() == Status::IntegrityFailure) {
    unindexedNodeIds_.erase(node.id);
    return;
  }
  unindexedNodeIds_.insert(node.id);
}

std::vector<RowReference> Client::rowsAwaitingMigratedIndex(const std::string& collection) const {
  std::vector<RowReference> rows;
  for (const std::string& nodeId : awaitingMigratedIndexIds_) {
    const Node* node = database_->findNode(nodeId);
    if (node->collection == collection) {
      rows.push_back(RowReference{nodeId, *node->schemaVersion});
    }
  }
  return rows;
}

Status Client::indexMigrated(const std::string& nodeId, const Json& content) {
  if (awaitingMigratedIndexIds_.count(nodeId) == 0) {
    lastContentError_ = contentError(Status::InvalidState, nodeId, "the row is not waiting for migrated content to be indexed");
    return Status::InvalidState;
  }
  if (!content.is_object()) {
    lastContentError_ = contentError(Status::InvalidArgument, nodeId, "the migrated content is not an object");
    return Status::InvalidArgument;
  }
  const Node& node = *database_->findNode(nodeId);
  Result<const TableDescriptor*> table = tableDescriptorFor(node.collection, *node.table);
  if (!table.ok()) {
    return table.status();
  }
  index_.defineIndexes(node.collection, table.value()->modelName, table.value()->indexes);
  index_.put(node.collection, nodeId, indexedNodeOf(*table.value(), content));
  awaitingMigratedIndexIds_.erase(nodeId);
  return Status::Ok;
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
    awaitingMigratedIndexIds_.erase(nodeId);
    unindexedNodeIds_.insert(nodeId);
  }
}

void Client::removeRowsOutOfReach(const std::vector<std::string>& nodeIds) {
  for (const std::string& nodeId : nodeIds) {
    const LocalNode* local = database_->findLocal(nodeId);
    if (local == nullptr || local->dirty) {
      continue;
    }
    keyring_.forgetNode(nodeId);
    database_->removeNode(nodeId);
  }
}

}  // namespace nw
