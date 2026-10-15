#include "client.hpp"
#include "files.hpp"
#include "node_content.hpp"

namespace nw {

namespace {

std::string registryDescriptorPath(const std::string& collection, const std::string& descriptorHash) {
  size_t slash = collection.find('/');
  std::string scope = collection.substr(1, slash - 1);
  std::string name = collection.substr(slash + 1);
  return "/api/v1/schemas/" + scope + "/" + name + "/descriptors/" + descriptorHash;
}

CodecError contentError(Status status, std::string path, std::string reason) {
  CodecError error;
  error.status = status;
  error.path = std::move(path);
  error.reason = std::move(reason);
  return error;
}

bool carriesContent(const Node& node) { return node.kind != "root" && !isShortcut(node); }

// A facet the node does not carry reads as empty, so its required fields are enforced.
void addAbsentFacets(const NodeDescriptor& descriptor, FacetMap& plaintexts) {
  for (const FacetDescriptor& facet : descriptor.facets) {
    plaintexts.try_emplace(facet.tag, Bytes());
  }
}

}  // namespace

// ── Descriptors ───────────────────────────────────────────────────────────────

Result<std::optional<DescriptorCheck>> Client::registerDescriptor(const std::string& collection,
                                                                  std::string_view descriptorText) {
  if (!isValidCollection(collection)) {
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
  registered.confirmed = database_->isDescriptorAccepted(collection, registered.descriptorHash);
  std::optional<DescriptorCheck> check;
  if (!registered.confirmed) {
    HttpRequest request;
    request.method = "GET";
    request.url = registryDescriptorPath(collection, registered.descriptorHash);
    check = DescriptorCheck{registered.descriptorHash, std::move(request)};
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

Result<const NodeDescriptor*> Client::nodeDescriptorFor(const std::string& collection, const std::string& kind) {
  const SchemaDescriptor* schema = descriptorFor(collection);
  if (schema == nullptr) {
    lastContentError_ = contentError(Status::InvalidState, collection, "no confirmed descriptor for the collection");
    return Status::InvalidState;
  }
  const NodeDescriptor* node = schema->nodeByKind(kind);
  if (node == nullptr) {
    lastContentError_ = contentError(Status::InvalidArgument, collection, "the schema has no " + kind + " model");
    return Status::InvalidArgument;
  }
  return node;
}

// ── Writes ────────────────────────────────────────────────────────────────────

Result<FacetMap> Client::encodeNewContent(const CreateNodeRequest& request) {
  if (request.kind == "root") {
    return FacetMap();
  }
  Result<const NodeDescriptor*> descriptor = nodeDescriptorFor(request.collection, request.kind);
  if (!descriptor.ok()) {
    return descriptor.status();
  }
  return encodeContent(*descriptor.value(), request.content, FacetMap(), false, lastContentError_);
}

Result<std::vector<NodeFile>> Client::filesOfContent(const std::string& collection, const std::string& kind,
                                                     const FacetMap& plaintexts) {
  if (kind == "root") {
    return std::vector<NodeFile>();
  }
  Result<const NodeDescriptor*> descriptor = nodeDescriptorFor(collection, kind);
  if (!descriptor.ok()) {
    return descriptor.status();
  }
  return filesOfFacets(*descriptor.value(), plaintexts, lastContentError_);
}

Result<std::string> Client::createNode(const CreateNodeRequest& request) {
  lastContentError_ = CodecError{};
  bool isRoot = request.kind == "root";
  bool validShape = isValidCollection(request.collection) && isValidKind(request.kind) &&
                    request.parentId.has_value() != isRoot;
  if (!validShape || (isRoot && (!request.content.is_object() || !request.content.empty()))) {
    return Status::InvalidArgument;
  }
  if (isRoot && signer_.authorType != "user") {
    return Status::Forbidden;
  }
  Node node;
  node.id = newUuid();
  node.parentId = request.parentId;
  node.collection = request.collection;
  node.kind = request.kind;
  node.epoch = 1;
  node.createdAt = nowText();
  node.updatedAt = node.createdAt;
  node.ownerId = signer_.authorId;
  SymmetricKey nodeKey = SymmetricKey::random();
  if (!isRoot) {
    Status attached = attachToParent(node, nodeKey);
    if (attached != Status::Ok) {
      return attached;
    }
  }
  Result<FacetMap> plaintexts = encodeNewContent(request);
  if (!plaintexts.ok()) {
    return plaintexts.status();
  }
  Result<std::vector<NodeFile>> files = filesOfContent(node.collection, node.kind, plaintexts.value());
  if (!files.ok()) {
    return files.status();
  }
  node.files = files.take();
  sealContent(node, nodeKey, plaintexts.value());
  Status stored = signAndStore(node);
  if (stored != Status::Ok) {
    return stored;
  }
  keyring_.addNodeKey(node.id, node.epoch, nodeKey.clone());
  indexPendingNodes();
  if (isRoot) {
    Status granted = createOwnerGrant(node, nodeKey);
    if (granted != Status::Ok) {
      return granted;
    }
  }
  grantReferencesToHolders(node.id);
  return node.id;
}

Result<std::string> Client::createShortcut(const CreateShortcutRequest& request) {
  const Node* target = database_->findNode(request.targetId);
  bool validRole = request.targetRole == "read" || request.targetRole == "write";
  if (!validRole || target == nullptr || target->deleted || target->kind != "item" || isShortcut(*target)) {
    return Status::InvalidArgument;
  }
  if (roleRank(effectiveRole(request.targetId)) < roleRank(request.targetRole)) {
    return Status::Forbidden;
  }
  Result<SymmetricKey> targetKey = resolveNodeKey(request.targetId);
  if (!targetKey.ok()) {
    return targetKey.status();
  }
  Node node;
  node.id = newUuid();
  node.parentId = request.parentId;
  node.collection = target->collection;
  node.kind = "item";
  // A shortcut's epoch names the target key it carries.
  node.epoch = target->epoch;
  node.targetId = request.targetId;
  node.targetRole = request.targetRole;
  node.createdAt = nowText();
  node.updatedAt = node.createdAt;
  Status attached = attachToParent(node, targetKey.value());
  if (attached != Status::Ok) {
    return attached;
  }
  Status stored = signAndStore(node);
  if (stored != Status::Ok) {
    return stored;
  }
  keyring_.addNodeKey(node.id, node.epoch, targetKey.value().clone());
  grantReferencesToHolders(node.id);
  return node.id;
}

Status Client::updateNode(const UpdateNodeRequest& request) {
  lastContentError_ = CodecError{};
  const LocalNode* local = database_->findLocal(request.nodeId);
  if (local == nullptr || local->node.deleted) {
    return Status::NotFound;
  }
  if (!request.changes.is_object() || (!carriesContent(local->node) && !request.changes.empty())) {
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
  FacetMap plaintexts = previous.value();
  if (carriesContent(local->node)) {
    Result<const NodeDescriptor*> descriptor = nodeDescriptorFor(local->node.collection, local->node.kind);
    if (!descriptor.ok()) {
      return descriptor.status();
    }
    Result<FacetMap> encoded = encodeContent(*descriptor.value(), request.changes, previous.value(), true, lastContentError_);
    if (!encoded.ok()) {
      return encoded.status();
    }
    plaintexts = encoded.take();
  }
  Node node = local->node;
  node.baseSeq = node.seq;
  node.updatedAt = nowText();
  if (carriesContent(node)) {
    Result<std::vector<NodeFile>> files = filesOfContent(node.collection, node.kind, plaintexts);
    if (!files.ok()) {
      return files.status();
    }
    node.files = files.take();
  }
  sealContent(node, nodeKey.value(), plaintexts);
  Status stored = signAndStore(node);
  if (stored == Status::Ok) {
    grantReferencesToHolders(node.id);
  }
  return stored;
}

Status Client::deleteNode(const std::string& nodeId, bool recursive) {
  const LocalNode* local = database_->findLocal(nodeId);
  if (local == nullptr) {
    return Status::NotFound;
  }
  if (roleRank(effectiveRole(nodeId)) < roleRank("write")) {
    return Status::Forbidden;
  }
  if (recursive) {
    for (const std::string& childId : database_->childrenOf(nodeId)) {
      Status childDeleted = deleteNode(childId, true);
      if (childDeleted != Status::Ok && childDeleted != Status::NotFound) {
        return childDeleted;
      }
    }
  }
  Node node = local->node;
  node.baseSeq = node.seq;
  node.deleted = true;
  node.content.clear();
  node.files.clear();
  node.updatedAt = nowText();
  return signAndStore(node);
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
  node.epoch = remote.epoch;
  node.wrappedKey = remote.wrappedKey;
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

Result<Json> Client::readContent(const Node& node, const SymmetricKey* nodeKey) {
  lastContentError_ = CodecError{};
  if (!carriesContent(node)) {
    return Json::object();
  }
  Result<const NodeDescriptor*> descriptor = nodeDescriptorFor(node.collection, node.kind);
  if (!descriptor.ok()) {
    return descriptor.status();
  }
  Result<FacetMap> readable = Status::NotFound;
  if (nodeKey != nullptr) {
    readable = openContent(node, *nodeKey);
    if (readable.ok()) {
      addAbsentFacets(*descriptor.value(), readable.value());
    }
  } else {
    NodeLookup lookup = nodeLookup();
    readable = readableFacets(node, *descriptor.value(),
                              [&](uint32_t tag) { return keyring_.resolveFacetKey(node, tag, lookup); });
  }
  if (!readable.ok()) {
    return readable.status();
  }
  if (readable.value().empty() && nodeKey == nullptr) {
    return Status::NotFound;
  }
#if defined(NW_ENABLE_TEST_HOOKS)
  ++contentDecryptions_;
#endif
  Result<Json> content = decodeContent(*descriptor.value(), readable.value(), lastContentError_);
  if (!content.ok()) {
    return content.status();
  }
  if (checkNodeFiles(*descriptor.value(), node, readable.value(), content.value()) != Status::Ok) {
    database_->recordIntegrityFailure(node.id, "file list does not match the content");
    return Status::IntegrityFailure;
  }
  return content;
}

Result<Json> Client::readNode(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted) {
    return Status::NotFound;
  }
  return readContent(*node, nullptr);
}

}  // namespace nw
