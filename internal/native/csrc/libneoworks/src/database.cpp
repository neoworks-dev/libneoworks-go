#include "database.hpp"

namespace nw {

namespace {

std::string grantKey(const AccessGrant& grant) {
  return grant.nodeId + "/" + grant.principalType + "/" + grant.principalId;
}

std::string shadowKey(const Node& node) { return node.id + "/" + std::to_string(node.seq) + "/" + node.updatedAt; }

Bytes encodeJson(const Json& json) { return bytesOf(dumpCompact(json)); }

using IdIndex = std::map<std::string, std::set<std::string>>;

void removeFromIndex(IdIndex& index, const std::string& key, const std::string& id) {
  auto found = index.find(key);
  if (found == index.end()) {
    return;
  }
  found->second.erase(id);
  if (found->second.empty()) {
    index.erase(found);
  }
}

std::vector<std::string> idsUnder(const IdIndex& index, const std::string& key) {
  auto found = index.find(key);
  if (found == index.end()) {
    return {};
  }
  return std::vector<std::string>(found->second.begin(), found->second.end());
}

std::optional<Json> decodeJson(const Bytes& plaintext) {
  return parseJson(std::string_view(reinterpret_cast<const char*>(plaintext.data()), plaintext.size()));
}

Json localNodeToJson(const LocalNode& local) {
  Json json = Json::object();
  json["node"] = nodeToJson(local.node);
  json["dirty"] = local.dirty;
  json["rejected"] = local.rejected;
  json["revision"] = local.revision;
  return json;
}

Json pinToJson(const PinnedIdentity& pin) {
  Json json = Json::object();
  json["identity"] = publicIdentityToJson(pin.identity);
  json["userVerified"] = pin.userVerified;
  json["pinnedAt"] = pin.pinnedAt;
  if (!pin.history.empty()) {
    json["history"] = identityHistoryToJson(pin.history);
  }
  return json;
}

Json certificateToJson(const StoredCertificate& stored) {
  Json json = Json::object();
  json["certificateBytes"] = bytesToJson(stored.certificateBytes);
  json["signature"] = bytesToJson(stored.signature);
  return json;
}

Json renewalCertificateToJson(const StoredRenewalCertificate& stored) {
  Json json = Json::object();
  json["renewalBytes"] = bytesToJson(stored.renewalBytes);
  json["signature"] = bytesToJson(stored.signature);
  return json;
}

}  // namespace

Result<std::unique_ptr<LocalDatabase>> LocalDatabase::open(std::unique_ptr<RecordBackend> backend,
                                                           SymmetricKey storeKey) {
  auto store = std::make_unique<EncryptedRecordStore>(std::move(backend), std::move(storeKey));
  std::unique_ptr<LocalDatabase> database(new LocalDatabase(std::move(store)));
  LocalDatabase* target = database.get();
  Status visited = target->store_->visitAll(
      [target](std::string_view kind, std::string_view key, const Bytes& plaintext) {
        target->load(kind, key, plaintext);
      },
      target->corruptRecords_);
  if (visited != Status::Ok) {
    return visited;
  }
  return database;
}

void LocalDatabase::load(std::string_view kind, std::string_view key, const Bytes& plaintext) {
  if (kind == "node") {
    loadNode(plaintext);
  } else if (kind == "grant") {
    loadGrant(plaintext);
  } else if (kind == "pin") {
    loadPin(plaintext);
  } else if (kind == "cert") {
    loadCertificate(plaintext);
  } else if (kind == "renewcert") {
    loadRenewalCertificate(plaintext);
  } else if (kind == "shadow") {
    loadShadow(plaintext);
  } else if (kind == "chain") {
    loadChain(plaintext);
  } else if (kind == "integrity") {
    loadIntegrity(key, plaintext);
  } else if (kind == "link") {
    loadLink(plaintext);
  } else if (kind == "outbox") {
    loadOutbox(key, plaintext);
  } else if (kind == "descriptor") {
    acceptedDescriptors_.insert(std::string(key));
  } else if (kind == "meta" && key == "cursor") {
    cursor_ = std::string(plaintext.begin(), plaintext.end());
  }
}

void LocalDatabase::loadNode(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value() || !json->contains("node")) {
    return;
  }
  Result<Node> node = nodeFromJson(json->at("node"));
  if (!node.ok()) {
    return;
  }
  LocalNode local;
  local.node = node.take();
  local.dirty = readBool(*json, "dirty").value_or(false);
  local.rejected = readBool(*json, "rejected").value_or(false);
  local.revision = readUnsigned(*json, "revision").value_or(0);
  storeLocalNode(std::move(local));
}

void LocalDatabase::loadGrant(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value()) {
    return;
  }
  Result<AccessGrant> grant = grantFromJson(*json);
  if (!grant.ok()) {
    return;
  }
  std::string key = grantKey(grant.value());
  grants_[key] = grant.take();
}

std::vector<IdentityVersion> PinnedIdentity::verificationKeys() const {
  if (history.empty()) {
    IdentityVersion only;
    only.signPub = identity.signPub;
    only.encPub = identity.encPub;
    return {only};
  }
  return std::vector<IdentityVersion>(history.rbegin(), history.rend());
}

const Bytes& PinnedIdentity::anchorSignPub() const {
  if (history.empty()) {
    return identity.signPub;
  }
  return history.front().signPub;
}

const Bytes& PinnedIdentity::anchorEncPub() const {
  if (history.empty()) {
    return identity.encPub;
  }
  return history.front().encPub;
}

void LocalDatabase::loadPin(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value() || !json->contains("identity")) {
    return;
  }
  Result<PublicIdentity> identity = publicIdentityFromJson(json->at("identity"));
  if (!identity.ok()) {
    return;
  }
  PinnedIdentity pin;
  pin.identity = identity.take();
  pin.userVerified = readBool(*json, "userVerified").value_or(false);
  pin.pinnedAt = readString(*json, "pinnedAt").value_or("");
  if (json->contains("history")) {
    Result<std::vector<IdentityVersion>> history = identityHistoryFromJson(json->at("history"));
    if (history.ok()) {
      pin.history = history.take();
    }
  }
  std::string userId = pin.identity.userId;
  pins_[userId] = std::move(pin);
}

void LocalDatabase::loadCertificate(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value()) {
    return;
  }
  std::optional<Bytes> certificateBytes = readBytes(*json, "certificateBytes");
  std::optional<Bytes> signature = readBytes(*json, "signature");
  if (!certificateBytes || !signature) {
    return;
  }
  Result<DelegationCertificate> parsed = parseTrustedCertificate(*certificateBytes);
  if (!parsed.ok()) {
    return;
  }
  StoredCertificate stored{parsed.take(), std::move(*certificateBytes), std::move(*signature)};
  std::string certId = stored.certificate.certId;
  certificates_[certId] = std::move(stored);
}

void LocalDatabase::loadRenewalCertificate(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value()) {
    return;
  }
  std::optional<Bytes> renewalBytes = readBytes(*json, "renewalBytes");
  std::optional<Bytes> signature = readBytes(*json, "signature");
  if (!renewalBytes || !signature) {
    return;
  }
  Result<RenewalCertificate> parsed = parseTrustedRenewalCertificate(*renewalBytes);
  if (!parsed.ok()) {
    return;
  }
  StoredRenewalCertificate stored{parsed.take(), std::move(*renewalBytes), std::move(*signature)};
  std::string renewalCertId = stored.renewal.renewalCertId;
  renewalCertificates_[renewalCertId] = std::move(stored);
}

void LocalDatabase::loadShadow(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value()) {
    return;
  }
  Result<Node> node = nodeFromJson(*json);
  if (!node.ok()) {
    return;
  }
  std::string key = shadowKey(node.value());
  shadows_[key] = node.take();
}

const LocalNode* LocalDatabase::findLocal(const std::string& nodeId) const {
  auto found = nodes_.find(nodeId);
  if (found == nodes_.end()) {
    return nullptr;
  }
  return &found->second;
}

const Node* LocalDatabase::findNode(const std::string& nodeId) const {
  const LocalNode* local = findLocal(nodeId);
  if (local == nullptr) {
    return nullptr;
  }
  return &local->node;
}

Status LocalDatabase::persistLocalNode(const LocalNode& local) {
  return store_->put("node", local.node.id, encodeJson(localNodeToJson(local)));
}

// Replaces the node's stored version in memory and in the indexes, without persisting it.
void LocalDatabase::storeLocalNode(LocalNode local) {
  std::string nodeId = local.node.id;
  auto existing = nodes_.find(nodeId);
  if (existing != nodes_.end()) {
    unindexNode(existing->second);
  }
  indexNode(local);
  nodes_[nodeId] = std::move(local);
}

void LocalDatabase::indexNode(const LocalNode& local) {
  const Node& node = local.node;
  if (node.parentId.has_value()) {
    childrenByParent_[*node.parentId].insert(node.id);
  }
  for (const std::string& target : node.links) {
    linkersByTarget_[target].insert(node.id);
  }
  nodesByCollection_[node.collection].insert(node.id);
  if (local.dirty) {
    dirtyNodeIds_.insert(node.id);
  }
}

void LocalDatabase::unindexNode(const LocalNode& local) {
  const Node& node = local.node;
  if (node.parentId.has_value()) {
    removeFromIndex(childrenByParent_, *node.parentId, node.id);
  }
  for (const std::string& target : node.links) {
    removeFromIndex(linkersByTarget_, target, node.id);
  }
  removeFromIndex(nodesByCollection_, node.collection, node.id);
  dirtyNodeIds_.erase(node.id);
}

Status LocalDatabase::putNode(Node node, bool dirty) {
  LocalNode local;
  const LocalNode* existing = findLocal(node.id);
  if (existing != nullptr) {
    local.revision = existing->revision;
  }
  local.node = std::move(node);
  local.dirty = dirty;
  if (dirty) {
    local.revision += 1;
  }
  std::string nodeId = local.node.id;
  storeLocalNode(std::move(local));
  Status persisted = persistLocalNode(nodes_.at(nodeId));
  notifyNodeChanged(nodeId);
  return persisted;
}

void LocalDatabase::notifyNodeChanged(const std::string& nodeId) const {
  if (nodeObserver_) {
    nodeObserver_(nodeId);
  }
}

Status LocalDatabase::putRemoteNode(Node node) { return putNode(std::move(node), false); }

Status LocalDatabase::markPushed(const std::string& nodeId, uint64_t seq, uint64_t pushedRevision) {
  auto found = nodes_.find(nodeId);
  if (found == nodes_.end()) {
    return Status::NotFound;
  }
  LocalNode& local = found->second;
  local.node.seq = seq;
  local.rejected = false;
  if (local.revision == pushedRevision) {
    local.dirty = false;
    dirtyNodeIds_.erase(nodeId);
  }
  return persistLocalNode(local);
}

Status LocalDatabase::markRejected(const std::string& nodeId) {
  auto found = nodes_.find(nodeId);
  if (found == nodes_.end()) {
    return Status::NotFound;
  }
  found->second.rejected = true;
  found->second.dirty = false;
  dirtyNodeIds_.erase(nodeId);
  return persistLocalNode(found->second);
}

Status LocalDatabase::removeNode(const std::string& nodeId) {
  auto found = nodes_.find(nodeId);
  if (found != nodes_.end()) {
    unindexNode(found->second);
    nodes_.erase(found);
  }
  Status removed = store_->remove("node", nodeId);
  notifyNodeChanged(nodeId);
  return removed;
}

std::vector<std::string> LocalDatabase::childrenOf(const std::string& parentId) const {
  return idsUnder(childrenByParent_, parentId);
}

std::vector<std::string> LocalDatabase::linkersOf(const std::string& targetId) const {
  return idsUnder(linkersByTarget_, targetId);
}

namespace {

std::string descriptorKey(const std::string& collection, const std::string& descriptorHash) {
  return collection + " " + descriptorHash;
}

}  // namespace

bool LocalDatabase::isDescriptorAccepted(const std::string& collection, const std::string& descriptorHash) const {
  return acceptedDescriptors_.count(descriptorKey(collection, descriptorHash)) != 0;
}

Status LocalDatabase::acceptDescriptor(const std::string& collection, const std::string& descriptorHash) {
  std::string key = descriptorKey(collection, descriptorHash);
  acceptedDescriptors_.insert(key);
  return store_->put("descriptor", key, bytesOf("1"));
}

std::vector<std::string> LocalDatabase::nodesInCollection(const std::string& collection) const {
  return idsUnder(nodesByCollection_, collection);
}

std::vector<std::string> LocalDatabase::dirtyNodeIds() const {
  return std::vector<std::string>(dirtyNodeIds_.begin(), dirtyNodeIds_.end());
}

std::vector<std::string> LocalDatabase::allNodeIds() const {
  std::vector<std::string> ids;
  for (const auto& entry : nodes_) {
    ids.push_back(entry.first);
  }
  return ids;
}

Status LocalDatabase::putGrant(const AccessGrant& grant) {
  grants_[grantKey(grant)] = grant;
  return store_->put("grant", grantKey(grant), encodeJson(grantToJson(grant)));
}

std::vector<AccessGrant> LocalDatabase::grantsForNode(const std::string& nodeId) const {
  std::vector<AccessGrant> result;
  for (auto entry = grants_.lower_bound(nodeId + "/"); entry != grants_.end() && entry->second.nodeId == nodeId;
       ++entry) {
    result.push_back(entry->second);
  }
  return result;
}

std::vector<AccessGrant> LocalDatabase::allGrants() const {
  std::vector<AccessGrant> result;
  for (const auto& entry : grants_) {
    result.push_back(entry.second);
  }
  return result;
}

Status LocalDatabase::setCursor(const std::string& cursor) {
  cursor_ = cursor;
  return store_->put("meta", "cursor", bytesOf(cursor));
}

const PinnedIdentity* LocalDatabase::findPin(const std::string& userId) const {
  auto found = pins_.find(userId);
  if (found == pins_.end()) {
    return nullptr;
  }
  return &found->second;
}

Status LocalDatabase::putPin(const PinnedIdentity& pin) {
  pins_[pin.identity.userId] = pin;
  return store_->put("pin", pin.identity.userId, encodeJson(pinToJson(pin)));
}

std::vector<PinnedIdentity> LocalDatabase::allPins() const {
  std::vector<PinnedIdentity> result;
  for (const auto& entry : pins_) {
    result.push_back(entry.second);
  }
  return result;
}

const StoredCertificate* LocalDatabase::findCertificate(const std::string& certId) const {
  auto found = certificates_.find(certId);
  if (found == certificates_.end()) {
    return nullptr;
  }
  return &found->second;
}

Status LocalDatabase::putCertificate(const StoredCertificate& stored) {
  certificates_[stored.certificate.certId] = stored;
  return store_->put("cert", stored.certificate.certId, encodeJson(certificateToJson(stored)));
}

const StoredRenewalCertificate* LocalDatabase::findRenewalCertificate(const std::string& renewalCertId) const {
  auto found = renewalCertificates_.find(renewalCertId);
  if (found == renewalCertificates_.end()) {
    return nullptr;
  }
  return &found->second;
}

Status LocalDatabase::putRenewalCertificate(const StoredRenewalCertificate& stored) {
  renewalCertificates_[stored.renewal.renewalCertId] = stored;
  return store_->put("renewcert", stored.renewal.renewalCertId, encodeJson(renewalCertificateToJson(stored)));
}

std::vector<StoredCertificate> LocalDatabase::allCertificates() const {
  std::vector<StoredCertificate> result;
  for (const auto& entry : certificates_) {
    result.push_back(entry.second);
  }
  return result;
}

void LocalDatabase::loadOutbox(std::string_view key, const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (json.has_value()) {
    outbox_[std::string(key)] = *json;
  }
}

Status LocalDatabase::putOutboxOperation(const std::string& operationId, const Json& operation) {
  outbox_[operationId] = operation;
  return store_->put("outbox", operationId, encodeJson(operation));
}

Status LocalDatabase::removeOutboxOperation(const std::string& operationId) {
  outbox_.erase(operationId);
  return store_->remove("outbox", operationId);
}

std::vector<std::pair<std::string, Json>> LocalDatabase::outboxOperations() const {
  std::vector<std::pair<std::string, Json>> result;
  for (const auto& entry : outbox_) {
    result.push_back(entry);
  }
  return result;
}

void LocalDatabase::loadChain(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value() || !json->is_array()) {
    return;
  }
  std::vector<AccessLogEntry> entries;
  for (const Json& item : *json) {
    Result<AccessLogEntry> entry = entryFromJson(item);
    if (!entry.ok()) {
      return;
    }
    entries.push_back(entry.take());
  }
  if (!entries.empty()) {
    std::string nodeId = entries.front().nodeId;
    chains_[nodeId] = std::move(entries);
  }
}

void LocalDatabase::loadIntegrity(std::string_view key, const Bytes& plaintext) {
  integrityFailures_[std::string(key)] = std::string(plaintext.begin(), plaintext.end());
}

std::vector<AccessLogEntry> LocalDatabase::chainOf(const std::string& nodeId) const {
  auto found = chains_.find(nodeId);
  if (found == chains_.end()) {
    return {};
  }
  return found->second;
}

std::optional<LogHead> LocalDatabase::headOf(const std::string& nodeId) const {
  auto found = chains_.find(nodeId);
  if (found == chains_.end() || found->second.empty()) {
    return std::nullopt;
  }
  const AccessLogEntry& last = found->second.back();
  return LogHead{last.index, entryHash(last)};
}

Status LocalDatabase::appendChainEntries(const std::string& nodeId, const std::vector<AccessLogEntry>& entries) {
  std::vector<AccessLogEntry>& chain = chains_[nodeId];
  chain.insert(chain.end(), entries.begin(), entries.end());
  Json json = Json::array();
  for (const AccessLogEntry& entry : chain) {
    json.push_back(entryToJson(entry));
  }
  return store_->put("chain", nodeId, encodeJson(json));
}

Status LocalDatabase::recordIntegrityFailure(const std::string& nodeId, const std::string& reason) {
  integrityFailures_[nodeId] = reason;
  return store_->put("integrity", nodeId, bytesOf(reason));
}

void LocalDatabase::loadLink(const Bytes& plaintext) {
  std::optional<Json> json = decodeJson(plaintext);
  if (!json.has_value()) {
    return;
  }
  std::optional<std::string> nodeId = readString(*json, "nodeId");
  std::optional<std::string> linkId = readString(*json, "linkId");
  std::optional<std::string> createdAt = readString(*json, "createdAt");
  bool wellFormed = true;
  std::optional<std::string> expiresAt = readOptionalString(*json, "expiresAt", wellFormed);
  if (nodeId && linkId && createdAt && wellFormed) {
    links_[*linkId] = LinkEntry{*nodeId, *linkId, *createdAt, expiresAt};
  }
}

Status LocalDatabase::putLink(const LinkEntry& link) {
  links_[link.linkId] = link;
  Json json = Json::object();
  json["nodeId"] = link.nodeId;
  json["linkId"] = link.linkId;
  json["createdAt"] = link.createdAt;
  json["expiresAt"] = Json(nullptr);
  if (link.expiresAt.has_value()) {
    json["expiresAt"] = *link.expiresAt;
  }
  return store_->put("link", link.linkId, encodeJson(json));
}

Status LocalDatabase::removeLink(const std::string& linkId) {
  links_.erase(linkId);
  return store_->remove("link", linkId);
}

const LinkEntry* LocalDatabase::findLink(const std::string& linkId) const {
  auto found = links_.find(linkId);
  if (found == links_.end()) {
    return nullptr;
  }
  return &found->second;
}

std::vector<LinkEntry> LocalDatabase::linksForNode(const std::string& nodeId) const {
  std::vector<LinkEntry> result;
  for (const auto& [linkId, link] : links_) {
    if (link.nodeId == nodeId) {
      result.push_back(link);
    }
  }
  return result;
}

Status LocalDatabase::saveShadow(const Node& losingVersion) {
  shadows_[shadowKey(losingVersion)] = losingVersion;
  return store_->put("shadow", shadowKey(losingVersion), encodeJson(nodeToJson(losingVersion)));
}

std::vector<Node> LocalDatabase::shadowsOf(const std::string& nodeId) const {
  std::vector<Node> result;
  for (const auto& [key, node] : shadows_) {
    if (node.id == nodeId) {
      result.push_back(node);
    }
  }
  return result;
}

Status LocalDatabase::wipe() {
  std::vector<std::string> removedNodeIds = allNodeIds();
  nodes_.clear();
  childrenByParent_.clear();
  linkersByTarget_.clear();
  nodesByCollection_.clear();
  dirtyNodeIds_.clear();
  grants_.clear();
  pins_.clear();
  certificates_.clear();
  renewalCertificates_.clear();
  shadows_.clear();
  outbox_.clear();
  links_.clear();
  chains_.clear();
  integrityFailures_.clear();
  acceptedDescriptors_.clear();
  cursor_.clear();
  Status cleared = store_->clear();
  for (const std::string& nodeId : removedNodeIds) {
    notifyNodeChanged(nodeId);
  }
  return cleared;
}

}  // namespace nw
