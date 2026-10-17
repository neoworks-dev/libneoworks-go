#include <algorithm>

#include "client.hpp"
#include "files.hpp"
#include "node_content.hpp"
#include "references.hpp"
#include "semver.hpp"

namespace nw {

namespace {

// The fields an app may see: Files without their keys and references as the ids of their rows.
void toAppContent(const TableDescriptor& table, Json& content) {
  removeFileKeys(*table.model, content);
  removeReferenceKeys(*table.model, content);
}

constexpr int kMaxMoveAncestorSteps = 64;

}  // namespace

CodecError contentError(Status status, std::string path, std::string reason) {
  CodecError error;
  error.status = status;
  error.path = std::move(path);
  error.reason = std::move(reason);
  return error;
}

// ── Descriptors ───────────────────────────────────────────────────────────────

Result<std::optional<DescriptorCheck>> Client::registerDescriptor(const std::string& collection,
                                                                  std::string_view descriptorText,
                                                                  std::string_view schemaVersion) {
  if (!isValidCollection(collection) || !parseSemverText(schemaVersion).has_value()) {
    return Status::InvalidArgument;
  }
  Result<std::shared_ptr<const SchemaDescriptor>> schema = parseDescriptor(descriptorText);
  if (!schema.ok()) {
    return schema.status();
  }
  RegisteredDescriptor registered;
  registered.schema = schema.take();
  registered.text = bytesOf(descriptorText);
  registered.descriptorHash = toBase64Url(hash(registered.text));
  registered.schemaVersion = std::string(schemaVersion);
  registered.confirmed = database_->isDescriptorAccepted(collection, registered.descriptorHash);
  std::optional<DescriptorCheck> check;
  if (!registered.confirmed) {
    check = DescriptorCheck{registered.descriptorHash, descriptorRequest(collection, registered.descriptorHash)};
  }
  descriptors_[collection] = std::move(registered);
  resetIndexOf(collection);
  indexPendingNodes();
  return check;
}

Status Client::completeDescriptorCheck(const std::string& collection, const HttpResponse& response) {
  auto found = descriptors_.find(collection);
  if (found == descriptors_.end()) {
    return Status::InvalidState;
  }
  RegisteredDescriptor& registered = found->second;
  if (response.status == 404 || (response.status == 200 && response.body != registered.text)) {
    return Status::AuthenticationFailed;
  }
  if (response.status != 200) {
    return Status::IoFailure;
  }
  registered.confirmed = true;
  Status accepted = database_->acceptDescriptor(collection, registered.descriptorHash);
  indexPendingNodes();
  return accepted;
}

const SchemaDescriptor* Client::descriptorFor(const std::string& collection) const {
  auto found = descriptors_.find(collection);
  if (found == descriptors_.end() || !found->second.confirmed) {
    return nullptr;
  }
  return found->second.schema.get();
}

Result<const TableDescriptor*> Client::tableDescriptorFor(const std::string& collection, const std::string& table) {
  const SchemaDescriptor* schema = descriptorFor(collection);
  if (schema == nullptr) {
    lastContentError_ = contentError(Status::InvalidState, collection, "no confirmed descriptor for the collection");
    return Status::InvalidState;
  }
  return tableIn(*schema, collection, table);
}

// ── Writes ────────────────────────────────────────────────────────────────────

Result<Json> Client::withFileKeys(const TableDescriptor& table, const TableDescriptor& storedTable,
                                  const Json& changes, const FacetMap& stored) {
  if (!holdsFile(*table.model, changes)) {
    return changes;
  }
  Result<Json> storedContent = decodeContent(storedTable, stored, lastContentError_);
  if (!storedContent.ok()) {
    return storedContent.status();
  }
  Json keyed = changes;
  Status assigned = assignFileKeys(*table.model, *storedTable.model, keyed, storedContent.value(), lastContentError_);
  if (assigned != Status::Ok) {
    return assigned;
  }
  return keyed;
}

Result<Json> Client::withKeys(const TableDescriptor& table, const TableDescriptor& storedTable, const Json& changes,
                              const FacetMap& stored) {
  Result<Json> keyed = withFileKeys(table, storedTable, changes, stored);
  if (!keyed.ok()) {
    return keyed;
  }
  RowKeyResolver keyFor = [this](const std::string& rowId, const std::string& referencedTable) {
    return referencedRowKey(rowId, referencedTable);
  };
  Status assigned = assignReferenceKeys(table, keyed.value(), keyFor, lastContentError_);
  if (assigned != Status::Ok) {
    return assigned;
  }
  return keyed;
}

Result<SymmetricKey> Client::referencedRowKey(const std::string& rowId, const std::string& table) {
  const Node* row = database_->findNode(rowId);
  if (row == nullptr || row->deleted || isRoot(*row)) {
    return Status::NotFound;
  }
  const SchemaDescriptor* schema = descriptorFor(row->collection);
  if (schema == nullptr) {
    return Status::NotFound;
  }
  if (schema->namespaceName + "." + *row->table != table) {
    return Status::InvalidArgument;
  }
  return resolveNodeKey(rowId);
}

Status Client::describeContent(const TableDescriptor& table, const FacetMap& plaintexts, Node& node) {
  Result<Json> content = decodeContent(table, plaintexts, lastContentError_);
  if (!content.ok()) {
    return content.status();
  }
  Result<std::vector<NodeFile>> files = collectFiles(*table.model, content.value());
  if (files.status() == Status::InvalidArgument) {
    lastContentError_ = contentError(Status::InvalidArgument, table.modelName, "an object id is used by more than one file");
  }
  if (!files.ok()) {
    return files.status();
  }
  node.files = files.take();
  node.links = linksOf(table, content.value());
  node.links.erase(std::remove(node.links.begin(), node.links.end(), node.id), node.links.end());
  return Status::Ok;
}

std::string Client::actingUserId() const {
  if (signer_.authorType == "user" || !certificate_.has_value()) {
    return signer_.authorId;
  }
  return certificate_->userId;
}

const Node* Client::ownRootOf(const std::string& collection) const {
  std::string userId = actingUserId();
  for (const std::string& nodeId : database_->nodesInCollection(collection)) {
    const Node* node = database_->findNode(nodeId);
    if (isRoot(*node) && !node->deleted && node->ownerId == userId) {
      return node;
    }
  }
  return nullptr;
}

Result<std::string> Client::parentOfNewRow(const std::string& collection, const TableDescriptor& table,
                                           const Json& content) {
  std::optional<std::string> owner = belongsToOf(table, content);
  if (owner.has_value()) {
    return *owner;
  }
  const Node* root = ownRootOf(collection);
  if (root == nullptr) {
    lastContentError_ = contentError(Status::NotFound, collection, "this holder has no root in the collection");
    return Status::NotFound;
  }
  return root->id;
}

Result<std::string> Client::createNode(const CreateNodeRequest& request) {
  lastContentError_ = CodecError{};
  if (!isValidCollection(request.collection)) {
    return Status::InvalidArgument;
  }
  if (request.kind == "root") {
    return createRoot(request);
  }
  if (request.kind != "row" || request.table.empty() || !request.content.is_object()) {
    return Status::InvalidArgument;
  }
  return createRow(request);
}

Result<std::string> Client::createRoot(const CreateNodeRequest& request) {
  if (!request.table.empty() || !request.content.is_object() || !request.content.empty()) {
    return Status::InvalidArgument;
  }
  if (signer_.authorType != "user") {
    return Status::Forbidden;
  }
  Node node;
  node.id = newUuid();
  node.collection = request.collection;
  node.kind = "root";
  node.createdAt = nowText();
  node.updatedAt = node.createdAt;
  node.ownerId = signer_.authorId;
  SymmetricKey nodeKey = SymmetricKey::random();
  Status stored = signAndStore(node);
  if (stored != Status::Ok) {
    return stored;
  }
  keyring_.addNodeKey(node.id, nodeKey.clone());
  Status granted = createOwnerGrant(node, nodeKey);
  if (granted != Status::Ok) {
    return granted;
  }
  return node.id;
}

Result<std::string> Client::createRow(const CreateNodeRequest& request) {
  Result<const TableDescriptor*> table = tableDescriptorFor(request.collection, request.table);
  if (!table.ok()) {
    return table.status();
  }
  Result<std::string> parentId = parentOfNewRow(request.collection, *table.value(), request.content);
  if (!parentId.ok()) {
    return parentId.status();
  }
  Node node;
  node.id = newUuid();
  node.parentId = parentId.take();
  node.collection = request.collection;
  node.kind = "row";
  node.table = request.table;
  node.createdAt = nowText();
  node.updatedAt = node.createdAt;
  SymmetricKey nodeKey = SymmetricKey::random();
  Status attached = attachToParent(node, nodeKey);
  if (attached != Status::Ok) {
    return attached;
  }
  Result<Json> keyed = withKeys(*table.value(), *table.value(), request.content, FacetMap());
  if (!keyed.ok()) {
    return keyed.status();
  }
  Result<FacetMap> plaintexts = encodeContent(*table.value(), keyed.value(), FacetMap(), false, lastContentError_);
  if (!plaintexts.ok()) {
    return plaintexts.status();
  }
  Status described = describeContent(*table.value(), plaintexts.value(), node);
  if (described != Status::Ok) {
    return described;
  }
  stampSchemaVersion(node, registeredVersion(request.collection));
  sealContent(node, nodeKey, plaintexts.value());
  Status stored = signAndStore(node);
  if (stored != Status::Ok) {
    return stored;
  }
  keyring_.addNodeKey(node.id, nodeKey.clone());
  indexPendingNodes();
  return node.id;
}

Status Client::updateNode(const UpdateNodeRequest& request) {
  lastContentError_ = CodecError{};
  const LocalNode* local = database_->findLocal(request.nodeId);
  if (local == nullptr || local->node.deleted) {
    return Status::NotFound;
  }
  if (!request.changes.is_object() || isRoot(local->node)) {
    return Status::InvalidArgument;
  }
  if (roleRank(effectiveRole(request.nodeId)) < roleRank("write")) {
    return Status::Forbidden;
  }
  Result<SymmetricKey> nodeKey = resolveNodeKey(request.nodeId);
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  Result<FacetMap> previous = openContent(local->node, nodeKey.value());
  if (!previous.ok()) {
    return previous.status();
  }
  Result<UpdatePlan> plan = planUpdate(local->node, request);
  if (!plan.ok()) {
    return plan.status();
  }
  Node node = local->node;
  Status moved = moveToNewParent(*plan.value().writeTable, request.changes, nodeKey.value(), node);
  if (moved != Status::Ok) {
    return moved;
  }
  Result<FacetMap> plaintexts = updatedPlaintexts(plan.value(), request, previous.value());
  if (!plaintexts.ok()) {
    return plaintexts.status();
  }
  node.baseSeq = node.seq;
  node.updatedAt = nowText();
  Status described = describeContent(*plan.value().writeTable, plaintexts.value(), node);
  if (described != Status::Ok) {
    return described;
  }
  stampSchemaVersion(node, plan.value().writeVersion);
  sealContent(node, nodeKey.value(), plaintexts.value());
  return signAndStore(node);
}

// A given @belongsTo field that names another row moves `node` below it: the row key stays and is
// wrapped under the new parent's key. Rows below `node` are not written.
Status Client::moveToNewParent(const TableDescriptor& table, const Json& changes, const SymmetricKey& nodeKey,
                               Node& node) {
  if (!table.belongsTo.has_value() || !changes.contains(table.model->fieldByOrdinal(*table.belongsTo)->name)) {
    return Status::Ok;
  }
  Result<std::string> newParentId = parentOfNewRow(node.collection, table, changes);
  if (!newParentId.ok()) {
    return newParentId.status();
  }
  if (node.parentId == newParentId.value()) {
    return Status::Ok;
  }
  Status placeable = checkMoveTarget(node, newParentId.value());
  if (placeable != Status::Ok) {
    return placeable;
  }
  node.parentId = newParentId.take();
  return attachToParent(node, nodeKey);
}

Status Client::checkMoveTarget(const Node& node, const std::string& newParentId) {
  if (roleRank(effectiveRole(*node.parentId)) < roleRank("write")) {
    return Status::Forbidden;
  }
  const Node* newParent = database_->findNode(newParentId);
  if (newParent == nullptr || newParent->deleted || newParent->collection != node.collection) {
    return Status::NotFound;
  }
  if (newParent->ownerId != node.ownerId) {
    lastContentError_ = contentError(Status::InvalidArgument, node.collection, "a row moves within the rows of its owner");
    return Status::InvalidArgument;
  }
  if (isSelfOrBelow(*newParent, node.id)) {
    lastContentError_ = contentError(Status::InvalidArgument, node.collection, "a row cannot move below itself");
    return Status::InvalidArgument;
  }
  return Status::Ok;
}

bool Client::isSelfOrBelow(const Node& candidate, const std::string& ancestorId) const {
  const Node* cursor = &candidate;
  for (int step = 0; step < kMaxMoveAncestorSteps && cursor != nullptr; ++step) {
    if (cursor->id == ancestorId) {
      return true;
    }
    if (!cursor->parentId.has_value()) {
      return false;
    }
    cursor = database_->findNode(*cursor->parentId);
  }
  return false;
}

Result<std::vector<std::string>> Client::deleteNode(const std::string& nodeId) {
  const LocalNode* local = database_->findLocal(nodeId);
  if (local == nullptr) {
    return Status::NotFound;
  }
  if (roleRank(effectiveRole(nodeId)) < roleRank("write")) {
    return Status::Forbidden;
  }
  DeletionPass pass;
  Status deleted = deleteRow(nodeId, pass);
  if (deleted != Status::Ok) {
    return deleted;
  }
  return std::move(pass.deletedIds);
}

Status Client::deleteRow(const std::string& nodeId, DeletionPass& pass) {
  if (!pass.visited.insert(nodeId).second) {
    return Status::Ok;
  }
  const LocalNode* local = database_->findLocal(nodeId);
  if (local == nullptr || local->node.deleted) {
    return Status::Ok;
  }
  Status linkersDeleted = deleteCascadingLinkers(nodeId, pass);
  if (linkersDeleted != Status::Ok) {
    return linkersDeleted;
  }
  for (const std::string& childId : database_->childrenOf(nodeId)) {
    Status childDeleted = deleteRow(childId, pass);
    if (childDeleted != Status::Ok) {
      return childDeleted;
    }
  }
  Node node = database_->findLocal(nodeId)->node;
  node.baseSeq = node.seq;
  node.deleted = true;
  node.content.clear();
  node.files.clear();
  node.links.clear();
  node.updatedAt = nowText();
  Status stored = signAndStore(node);
  if (stored == Status::Ok) {
    pass.deletedIds.push_back(nodeId);
  }
  return stored;
}

// Rows linking to the target through a cascading reference go with it, where this holder may write
// them; the others keep a dead link until someone who may write them removes it.
Status Client::deleteCascadingLinkers(const std::string& targetId, DeletionPass& pass) {
  for (const std::string& linkerId : database_->linkersOf(targetId)) {
    const Node* linker = database_->findNode(linkerId);
    bool writable = linker != nullptr && !linker->deleted && roleRank(effectiveRole(linkerId)) >= roleRank("write");
    if (!writable || !cascadesFrom(*linker, targetId)) {
      continue;
    }
    Status linkerDeleted = deleteRow(linkerId, pass);
    if (linkerDeleted != Status::Ok) {
      return linkerDeleted;
    }
  }
  return Status::Ok;
}

bool Client::cascadesFrom(const Node& linker, const std::string& targetId) {
  CodecError callerError = lastContentError_;
  Result<StoredContent> stored = readStoredContent(linker, nullptr);
  lastContentError_ = callerError;
  if (!stored.ok()) {
    return false;
  }
  const TableDescriptor& table = *stored.value().table;
  std::vector<ContentReference> references = collectReferences(*table.model, stored.value().content);
  return std::any_of(references.begin(), references.end(), [&](const ContentReference& reference) {
    return reference.rowId == targetId && table.cascades(reference.fieldOrdinal);
  });
}

Status Client::rebaseLocalNode(const std::string& nodeId, const Node& remote) {
  const LocalNode* local = database_->findLocal(nodeId);
  if (local == nullptr) {
    return Status::NotFound;
  }
  Result<SymmetricKey> localKey = keyring_.resolveNodeKey(local->node, nodeLookup());
  if (!localKey.ok()) {
    return localKey.status();
  }
  Result<FacetMap> plaintexts = openContent(local->node, localKey.value());
  if (!plaintexts.ok()) {
    return plaintexts.status();
  }
  Node node = local->node;
  node.baseSeq = remote.seq;
  node.seq = remote.seq;
  Result<SymmetricKey> nodeKey = keyring_.resolveNodeKey(node, nodeLookup());
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  sealContent(node, nodeKey.value(), plaintexts.value());
  return signAndStore(node);
}

// ── Reads ─────────────────────────────────────────────────────────────────────

Result<Client::StoredContent> Client::readStoredContent(const Node& node, const SymmetricKey* nodeKey) {
  lastContentError_ = CodecError{};
  NodeLookup lookup = nodeLookup();
  FacetKeyResolver keyFor = [&](uint32_t tag) -> Result<SymmetricKey> {
    if (nodeKey != nullptr) {
      return facetKey(*nodeKey, tag);
    }
    return keyring_.resolveFacetKey(node, tag, lookup);
  };
  Result<const TableDescriptor*> table = tableOfRow(node);
  if (!table.ok()) {
    return table.status();
  }
  Result<FacetMap> readable = readableFacets(node, *table.value(), keyFor);
  if (!readable.ok()) {
    return readable.status();
  }
  if (readable.value().empty() && nodeKey == nullptr) {
    return Status::NotFound;
  }
#if defined(NW_ENABLE_TEST_HOOKS)
  ++contentDecryptions_;
#endif
  Result<Json> content = decodeContent(*table.value(), readable.value(), lastContentError_);
  if (!content.ok()) {
    return content.status();
  }
  if (checkNodeFiles(*table.value(), node, content.value()) != Status::Ok) {
    database_->recordIntegrityFailure(node.id, "file list does not match the content");
    return Status::IntegrityFailure;
  }
  return StoredContent{table.value(), content.take()};
}

Result<Json> Client::readContent(const Node& node, const SymmetricKey* nodeKey) {
  if (isRoot(node)) {
    return Json::object();
  }
  Result<StoredContent> stored = readStoredContent(node, nodeKey);
  if (!stored.ok()) {
    return stored.status();
  }
  toAppContent(*stored.value().table, stored.value().content);
  return std::move(stored.value().content);
}

Result<SymmetricKey> Client::resolveFileKey(const std::string& nodeId, const std::string& objectId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || isRoot(*node)) {
    return Status::NotFound;
  }
  Result<StoredContent> stored = readStoredContent(*node, nullptr);
  if (!stored.ok()) {
    return stored.status();
  }
  return findFileKey(*stored.value().table->model, stored.value().content, objectId);
}

Result<SymmetricKey> Client::keyThroughLinks(const Node& target) {
  if (!rowsResolvingThroughLinks_.insert(target.id).second) {
    return Status::NotFound;
  }
  CodecError callerError = lastContentError_;
  Result<SymmetricKey> found = Status::NotFound;
  for (const std::string& linkerId : database_->linkersOf(target.id)) {
    const Node* linker = database_->findNode(linkerId);
    if (linker == nullptr || linker->deleted) {
      continue;
    }
    Result<StoredContent> stored = readStoredContent(*linker, nullptr);
    if (stored.ok()) {
      found = findReferenceKey(*stored.value().table->model, stored.value().content, target.id);
    }
    if (found.ok()) {
      break;
    }
  }
  lastContentError_ = callerError;
  rowsResolvingThroughLinks_.erase(target.id);
  return found;
}

Result<Json> Client::readNode(const std::string& nodeId) {
  Result<RowRead> row = readRow(nodeId);
  if (!row.ok()) {
    return row.status();
  }
  return row.take().content;
}

std::optional<std::string> Client::tableOf(const std::string& nodeId) const {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr) {
    return std::nullopt;
  }
  return node->table;
}

}  // namespace nw
