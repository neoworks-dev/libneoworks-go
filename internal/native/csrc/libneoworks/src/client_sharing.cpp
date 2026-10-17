#include <sodium.h>

#include <algorithm>

#include "client.hpp"
#include "key_history.hpp"
#include "tlv.hpp"

namespace nw {

Result<Bytes> Client::encPubFor(const std::string& principalType, const std::string& principalId) const {
  if (principalType == signer_.authorType && principalId == signer_.authorId) {
    return encPub_;
  }
  if (principalType == "user") {
    const PinnedIdentity* pin = database_->findPin(principalId);
    if (pin == nullptr) {
      return Status::NotFound;
    }
    return pin->identity.encPub;
  }
  for (const StoredCertificate& stored : database_->allCertificates()) {
    if (stored.certificate.installId == principalId) {
      return stored.certificate.installEncPub;
    }
  }
  return Status::NotFound;
}

std::string Client::trustedOwnerOf(const Node& node) const {
  const Node* root = &node;
  for (int step = 0; step < 64 && root->parentId.has_value(); ++step) {
    const Node* parent = database_->findNode(*root->parentId);
    if (parent == nullptr) {
      break;
    }
    root = parent;
  }
  std::vector<AccessLogEntry> chain = database_->chainOf(root->id);
  if (!chain.empty()) {
    return chain.front().actorId;
  }
  return root->ownerId;
}

// The owner may manage access; so may an install acting for the owner that holds the share scope.
bool Client::canManageAccess(const Node& node) const {
  std::string owner = trustedOwnerOf(node);
  if (signer_.authorType == "user") {
    return signer_.authorId == owner;
  }
  if (!certificate_.has_value()) {
    return false;
  }
  bool actsForOwner = certificate_->userId == owner && certificateAllows(*certificate_, node.collection + ":share");
  return actsForOwner && roleRank(effectiveRole(node.id)) >= roleRank("write");
}

Result<std::string> Client::grantCertificateFor(const std::string& principalType,
                                                const std::string& principalId) const {
  if (signer_.authorType == "install") {
    if (principalType != "user" || !signer_.certId.has_value()) {
      return Status::Forbidden;
    }
    return *signer_.certId;
  }
  if (principalType != "install") {
    return std::string();
  }
  for (const StoredCertificate& stored : database_->allCertificates()) {
    if (stored.certificate.installId == principalId) {
      return stored.certificate.certId;
    }
  }
  return Status::NotFound;
}

Result<AccessGrant> Client::grantNode(const ShareRequest& request) {
  const Node* node = database_->findNode(request.nodeId);
  if (node == nullptr) {
    return Status::NotFound;
  }
  Result<std::string> certId = grantCertificateFor(request.principalType, request.principalId);
  if (!certId.ok()) {
    return certId.status();
  }
  Result<SymmetricKey> nodeKey = resolveNodeKey(request.nodeId);
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  GrantRequest grantRequest;
  grantRequest.nodeId = request.nodeId;
  grantRequest.principalType = request.principalType;
  grantRequest.principalId = request.principalId;
  grantRequest.role = request.role;
  grantRequest.facets = request.facets;
  grantRequest.epoch = node->epoch;
  grantRequest.principalEncPub = request.principalEncPub;
  grantRequest.grantedByType = signer_.authorType;
  grantRequest.grantedById = signer_.authorId;
  if (!certId.value().empty()) {
    grantRequest.certId = certId.value();
  }
  grantRequest.createdAt = nowText();
  Result<AccessGrant> grant = createGrant(grantRequest, nodeKey.value());
  if (!grant.ok()) {
    return grant.status();
  }
  Status stored = database_->putGrant(grant.value());
  if (stored != Status::Ok) {
    return stored;
  }
  Status queued = queueGrant(grant.value());
  if (queued != Status::Ok) {
    return queued;
  }
  return grant;
}

Result<AccessGrant> Client::shareNode(const ShareRequest& request) {
  lastContentError_ = CodecError{};
  const Node* node = database_->findNode(request.nodeId);
  if (node == nullptr || node->deleted) {
    return Status::NotFound;
  }
  bool allowed = canManageAccess(*node) || (request.principalType == "install" && signer_.authorType == "user");
  bool withinOwnRole = roleRank(request.role) <= roleRank(effectiveRole(request.nodeId));
  if (!allowed || !withinOwnRole || !isValidRole(request.role)) {
    return Status::Forbidden;
  }
  return grantNode(request);
}

Status Client::queueRevocation(const std::string& nodeId, const std::string& principalType,
                               const std::string& principalId) {
  Json operation = Json::object();
  operation["op"] = "revoke";
  operation["nodeId"] = nodeId;
  operation["principalType"] = principalType;
  operation["principalId"] = principalId;
  return database_->putOutboxOperation(nextOutboxId(), operation);
}

struct Client::RotationStep {
  std::string nodeId;
  Node node;
  FacetMap plaintexts;
  std::vector<AccessGrant> remainingGrants;
  std::vector<Bytes> remainingEncPubs;
  SymmetricKey oldKey;
  SymmetricKey newKey;
  uint32_t newEpoch = 0;
};

namespace {

constexpr int kMaxAncestorWalk = 64;

bool isExcluded(const AccessGrant& grant, const std::string& removedType, const std::string& removedId) {
  return grant.principalType == removedType && grant.principalId == removedId;
}

}  // namespace

Result<Client::RotationStep> Client::planNodeRotation(const Node& node, const std::string& removedType,
                                                      const std::string& removedId) {
  RotationStep step;
  step.nodeId = node.id;
  step.node = node;
  Result<SymmetricKey> oldKey = keyring_.resolveNodeKey(node, nodeLookup());
  if (!oldKey.ok()) {
    return oldKey.status();
  }
  Result<FacetMap> plaintexts = openContent(node, oldKey.value());
  if (!plaintexts.ok()) {
    return plaintexts.status();
  }
  step.plaintexts = plaintexts.take();
  for (const AccessGrant& grant : database_->grantsForNode(node.id)) {
    if (grant.revokedAt.has_value() || isExcluded(grant, removedType, removedId)) {
      continue;
    }
    if (signer_.authorType == "install" && grant.principalType == "install") {
      return Status::Forbidden;
    }
    Result<Bytes> encPub = encPubFor(grant.principalType, grant.principalId);
    if (!encPub.ok()) {
      return encPub.status();
    }
    step.remainingGrants.push_back(grant);
    step.remainingEncPubs.push_back(encPub.take());
  }
  if (!step.remainingGrants.empty() && !canManageAccess(node)) {
    return Status::Forbidden;
  }
  step.oldKey = oldKey.take();
  step.newKey = SymmetricKey::random();
  step.newEpoch = node.epoch + 1;
  return step;
}

Status Client::applyRotationStep(RotationStep& step, const SymmetricKey* newParentKey, uint32_t newParentEpoch) {
  Node node = step.node;
  node.epoch = step.newEpoch;
  node.baseSeq = node.seq;
  node.updatedAt = nowText();
  if (node.parentId.has_value()) {
    node.wrappedKey = wrapNodeKey(*newParentKey, step.newKey, node.id, node.parentId, node.epoch, newParentEpoch);
  }
  sealContent(node, step.newKey, step.plaintexts);
  Status stored = signAndStore(node);
  if (stored != Status::Ok) {
    return stored;
  }
  keyring_.addNodeKey(node.id, node.epoch, step.newKey.clone());
  indexPendingNodes();
  for (size_t index = 0; index < step.remainingGrants.size(); ++index) {
    Status reissued = reissueGrant(step.remainingGrants[index], step.remainingEncPubs[index], node.epoch, step.newKey);
    if (reissued != Status::Ok) {
      return reissued;
    }
  }
  return Status::Ok;
}

Status Client::reissueGrant(const AccessGrant& old, const Bytes& encPub, uint32_t epoch, const SymmetricKey& nodeKey) {
  GrantRequest request;
  request.nodeId = old.nodeId;
  request.principalType = old.principalType;
  request.principalId = old.principalId;
  request.role = old.role;
  request.facets = old.facets;
  request.epoch = epoch;
  request.principalEncPub = encPub;
  request.grantedByType = signer_.authorType;
  request.grantedById = signer_.authorId;
  Result<std::string> certId = grantCertificateFor(old.principalType, old.principalId);
  if (!certId.ok()) {
    return certId.status();
  }
  if (!certId.value().empty()) {
    request.certId = certId.value();
  }
  request.createdAt = nowText();
  Result<AccessGrant> grant = createGrant(request, nodeKey);
  if (!grant.ok()) {
    return grant.status();
  }
  database_->putGrant(grant.value());
  return queueGrant(grant.value());
}

// A new key at the next epoch, wrapped under the parent's current key, with the old one kept in the
// key history; the records below stay wrapped under the old key until their own next change.
Status Client::rotateNode(const std::string& nodeId, const std::string& removedType, const std::string& removedId,
                          const ContentChange* change, RotationReport& report) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted || isShortcut(*node)) {
    return Status::NotFound;
  }
  if (roleRank(effectiveRole(nodeId)) < roleRank("write")) {
    return Status::Forbidden;
  }
  Result<RotationStep> step = planNodeRotation(*node, removedType, removedId);
  if (!step.ok()) {
    return step.status();
  }
  if (change != nullptr) {
    step.value().plaintexts = change->plaintexts;
    step.value().node.files = change->files;
    stampSchemaVersion(step.value().node);
  }
  Status kept = appendKeyHistory(step.value().plaintexts, node->epoch, step.value().oldKey);
  if (kept != Status::Ok) {
    return kept;
  }
  SymmetricKey parentKey;
  uint32_t parentEpoch = 0;
  Status parentStatus = currentParentKey(step.value().node, parentKey, parentEpoch);
  if (parentStatus != Status::Ok) {
    return parentStatus;
  }
  Status applied = applyRotationStep(step.value(), &parentKey, parentEpoch);
  if (applied != Status::Ok) {
    return applied;
  }
  report.rotatedNodeIds.push_back(nodeId);
  if (step.value().node.kind != "item") {
    return Status::Ok;
  }
  return rekeyShortcuts(nodeId, step.value().newKey, step.value().newEpoch, report);
}

// A shortcut carries its target's key wrapped under its parent, so every shortcut to a target that got a
// new key is wrapped again with it, under a parent whose own key is current.
Status Client::rekeyShortcuts(const std::string& targetId, const SymmetricKey& targetKey, uint32_t targetEpoch,
                              RotationReport& report) {
  for (const std::string& shortcutId : database_->shortcutsTo(targetId)) {
    const Node* shortcut = database_->findNode(shortcutId);
    if (!canRewrapShortcut(*shortcut)) {
      continue;
    }
    Status refreshed = refreshKeys(*shortcut->parentId, report);
    if (refreshed != Status::Ok) {
      return refreshed;
    }
    Status rekeyed = rekeyShortcut(shortcutId, targetKey, targetEpoch);
    if (rekeyed != Status::Ok) {
      return rekeyed;
    }
    report.rotatedNodeIds.push_back(shortcutId);
  }
  return Status::Ok;
}

Status Client::rekeyShortcut(const std::string& shortcutId, const SymmetricKey& targetKey, uint32_t targetEpoch) {
  Result<RotationStep> step = planNodeRotation(*database_->findNode(shortcutId), "", "");
  if (!step.ok()) {
    return step.status();
  }
  step.value().newKey = targetKey.clone();
  step.value().newEpoch = targetEpoch;
  SymmetricKey parentKey;
  uint32_t parentEpoch = 0;
  Status parentStatus = currentParentKey(step.value().node, parentKey, parentEpoch);
  if (parentStatus != Status::Ok) {
    return parentStatus;
  }
  return applyRotationStep(step.value(), &parentKey, parentEpoch);
}

Status Client::currentParentKey(const Node& node, SymmetricKey& parentKey, uint32_t& parentEpoch) {
  if (!node.parentId.has_value()) {
    return Status::Ok;
  }
  const Node* parent = database_->findNode(*node.parentId);
  if (parent == nullptr) {
    return Status::NotFound;
  }
  Result<SymmetricKey> resolved = keyring_.resolveNodeKey(*parent, nodeLookup());
  if (!resolved.ok()) {
    return resolved.status();
  }
  parentKey = resolved.take();
  parentEpoch = parent->epoch;
  return Status::Ok;
}

Client::Wrapping Client::wrappingOf(const Node& node) {
  if (!node.parentId.has_value() || !node.wrappedKey.has_value()) {
    return Wrapping::Unknown;
  }
  const Node* parent = database_->findNode(*node.parentId);
  if (parent == nullptr) {
    return Wrapping::Unknown;
  }
  Result<SymmetricKey> parentKey = keyring_.resolveNodeKey(*parent, nodeLookup());
  if (!parentKey.ok()) {
    return Wrapping::Unknown;
  }
  Result<SymmetricKey> unwrapped =
      unwrapNodeKey(parentKey.value(), *node.wrappedKey, node.id, node.parentId, node.epoch, parent->epoch);
  if (!unwrapped.ok()) {
    return Wrapping::Stale;
  }
  return Wrapping::Current;
}

std::vector<std::string> Client::exposedChainOf(const std::string& nodeId) {
  std::vector<std::string> path;
  size_t exposedLength = 0;
  const Node* cursor = database_->findNode(nodeId);
  for (int step = 0; step < kMaxAncestorWalk && cursor != nullptr; ++step) {
    path.push_back(cursor->id);
    Wrapping wrapping = wrappingOf(*cursor);
    if (wrapping == Wrapping::Unknown) {
      break;
    }
    if (wrapping == Wrapping::Stale) {
      exposedLength = path.size();
    }
    cursor = database_->findNode(*cursor->parentId);
  }
  path.resize(exposedLength);
  std::reverse(path.begin(), path.end());
  return path;
}

// Shortcuts in someone else's tree that this holder may only read are theirs to wrap again.
bool Client::canRewrapShortcut(const Node& shortcut) {
  bool parentKnown = !shortcut.deleted && resolveNodeKey(*shortcut.parentId).ok();
  return parentKnown && roleRank(effectiveRole(shortcut.id)) >= roleRank("write");
}

bool Client::isExposedThroughShortcuts(const Node& node) {
  if (node.kind != "item") {
    return false;
  }
  for (const std::string& shortcutId : database_->shortcutsTo(node.id)) {
    const Node* shortcut = database_->findNode(shortcutId);
    if (canRewrapShortcut(*shortcut) && !exposedChainOf(shortcutId).empty()) {
      return true;
    }
  }
  return false;
}

Result<bool> Client::refreshAncestors(const std::string& nodeId, RotationReport& report) {
  std::vector<std::string> chain = exposedChainOf(nodeId);
  for (const std::string& exposedId : chain) {
    if (exposedId == nodeId) {
      break;
    }
    Status rotated = rotateNode(exposedId, "", "", nullptr, report);
    if (rotated != Status::Ok) {
      return rotated;
    }
  }
  return !chain.empty();
}

Status Client::refreshKeys(const std::string& nodeId, RotationReport& report) {
  Result<bool> exposed = refreshAncestors(nodeId, report);
  if (!exposed.ok()) {
    return exposed.status();
  }
  if (!exposed.value()) {
    return Status::Ok;
  }
  return rotateNode(nodeId, "", "", nullptr, report);
}

Result<bool> Client::writeUnderNewKey(const std::string& nodeId, const ContentChange& change) {
  RotationReport report;
  Result<bool> exposed = refreshAncestors(nodeId, report);
  if (!exposed.ok()) {
    return exposed.status();
  }
  if (!exposed.value() && !isExposedThroughShortcuts(*database_->findNode(nodeId))) {
    return false;
  }
  Status rotated = rotateNode(nodeId, "", "", &change, report);
  if (rotated != Status::Ok) {
    return rotated;
  }
  return true;
}

Result<RotationReport> Client::revokeAccess(const std::string& nodeId, const std::string& principalType,
                                            const std::string& principalId) {
  const Node* targetNode = database_->findNode(nodeId);
  if (targetNode == nullptr || !canManageAccess(*targetNode)) {
    return Status::Forbidden;
  }
  std::optional<AccessGrant> target;
  for (const AccessGrant& grant : database_->grantsForNode(nodeId)) {
    if (grant.principalType == principalType && grant.principalId == principalId && !grant.revokedAt.has_value()) {
      target = grant;
    }
  }
  if (!target.has_value()) {
    return Status::NotFound;
  }
  RotationReport report;
  Result<bool> refreshed = refreshAncestors(nodeId, report);
  if (!refreshed.ok()) {
    return refreshed.status();
  }
  Status rotated = rotateNode(nodeId, principalType, principalId, nullptr, report);
  if (rotated != Status::Ok) {
    return rotated;
  }
  AccessGrant revoked = *target;
  revoked.revokedAt = nowText();
  database_->putGrant(revoked);
  queueRevocation(nodeId, principalType, principalId);
  return report;
}

Result<std::string> Client::createLinkFragment(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted) {
    return Status::NotFound;
  }
  if (!canManageAccess(*node)) {
    return Status::Forbidden;
  }
  Result<SymmetricKey> nodeKey = resolveNodeKey(nodeId);
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  Bytes fragment{static_cast<uint8_t>(node->epoch >> 24), static_cast<uint8_t>(node->epoch >> 16),
                 static_cast<uint8_t>(node->epoch >> 8), static_cast<uint8_t>(node->epoch)};
  appendTo(fragment, nodeKey.value().view());
  std::string encoded = toBase64Url(fragment);
  sodium_memzero(fragment.data(), fragment.size());
  return encoded;
}

Status Client::recordLink(const std::string& nodeId, const std::string& linkId) {
  if (database_->findNode(nodeId) == nullptr) {
    return Status::NotFound;
  }
  return database_->putLink(LinkEntry{nodeId, linkId, nowText()});
}

std::vector<LinkRecord> Client::linksFor(const std::string& nodeId) const {
  std::vector<LinkRecord> records;
  for (const LinkEntry& entry : database_->linksForNode(nodeId)) {
    records.push_back(LinkRecord{entry.nodeId, entry.linkId, entry.createdAt});
  }
  return records;
}

Result<RotationReport> Client::revokeLink(const std::string& linkId) {
  const LinkEntry* link = database_->findLink(linkId);
  if (link == nullptr) {
    return Status::NotFound;
  }
  std::string nodeId = link->nodeId;
  const Node* linkedNode = database_->findNode(nodeId);
  if (linkedNode == nullptr || !canManageAccess(*linkedNode)) {
    return Status::Forbidden;
  }
  RotationReport report;
  Result<bool> refreshed = refreshAncestors(nodeId, report);
  if (!refreshed.ok()) {
    return refreshed.status();
  }
  Status rotated = rotateNode(nodeId, "", "", nullptr, report);
  if (rotated != Status::Ok) {
    return rotated;
  }
  Json operation = Json::object();
  operation["op"] = "link-revoke";
  operation["nodeId"] = nodeId;
  operation["linkId"] = linkId;
  database_->putOutboxOperation(nextOutboxId(), operation);
  database_->removeLink(linkId);
  return report;
}

}  // namespace nw
