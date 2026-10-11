#include <sodium.h>

#include <algorithm>
#include <deque>

#include "client.hpp"
#include "tlv.hpp"

namespace nw {

namespace {

constexpr size_t kMaxRotationNodes = 100000;


}  // namespace

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

Result<AccessGrant> Client::shareNode(const ShareRequest& request) {
  const Node* node = database_->findNode(request.nodeId);
  if (node == nullptr || node->deleted) {
    return Status::NotFound;
  }
  bool allowed = canManageAccess(*node) || (request.principalType == "install" && signer_.authorType == "user");
  bool withinOwnRole = roleRank(request.role) <= roleRank(effectiveRole(request.nodeId));
  if (!allowed || !withinOwnRole || !isValidRole(request.role)) {
    return Status::Forbidden;
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
  SymmetricKey newKey;
  uint32_t newEpoch = 0;
  // A shortcut's key and epoch are its target's; only its wrapping under the parent changes.
  bool isShortcut = false;
};

namespace {

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
  step.isShortcut = isShortcut(node);
  step.newKey = SymmetricKey::random();
  step.newEpoch = node.epoch + 1;
  if (step.isShortcut) {
    step.newKey = oldKey.value().clone();
    step.newEpoch = node.epoch;
  }
  return step;
}

Result<std::vector<Client::RotationStep>> Client::planRotation(const std::string& nodeId,
                                                               const std::string& removedType,
                                                               const std::string& removedId) {
  std::vector<RotationStep> steps;
  std::deque<std::string> queue{nodeId};
  while (!queue.empty()) {
    if (steps.size() > kMaxRotationNodes) {
      return Status::Malformed;
    }
    const Node* node = database_->findNode(queue.front());
    queue.pop_front();
    if (node == nullptr || node->deleted) {
      continue;
    }
    Result<RotationStep> step = planNodeRotation(*node, removedType, removedId);
    if (!step.ok()) {
      return step.status();
    }
    steps.push_back(step.take());
    for (const std::string& childId : database_->childrenOf(node->id)) {
      queue.push_back(childId);
    }
  }
  return steps;
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
  for (size_t index = 0; index < step.remainingGrants.size(); ++index) {
    const AccessGrant& old = step.remainingGrants[index];
    GrantRequest request;
    request.nodeId = old.nodeId;
    request.principalType = old.principalType;
    request.principalId = old.principalId;
    request.role = old.role;
    request.facets = old.facets;
    request.epoch = node.epoch;
    request.principalEncPub = step.remainingEncPubs[index];
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
    Result<AccessGrant> grant = createGrant(request, step.newKey);
    if (!grant.ok()) {
      return grant.status();
    }
    database_->putGrant(grant.value());
    queueGrant(grant.value());
  }
  return Status::Ok;
}

Result<RotationReport> Client::rotateSubtree(const std::string& nodeId, const std::string& removedType,
                                             const std::string& removedId) {
  Result<std::vector<RotationStep>> plan = planRotation(nodeId, removedType, removedId);
  if (!plan.ok()) {
    return plan.status();
  }
  RotationReport report;
  std::map<std::string, std::pair<SymmetricKey, uint32_t>> rotated;
  for (RotationStep& step : plan.value()) {
    SymmetricKey parentKey;
    uint32_t parentEpoch = 0;
    Status parentStatus = parentForStep(step, rotated, parentKey, parentEpoch);
    if (parentStatus != Status::Ok) {
      return parentStatus;
    }
    Status applied = applyRotationStep(step, &parentKey, parentEpoch);
    if (applied != Status::Ok) {
      return applied;
    }
    rotated.emplace(step.nodeId, std::make_pair(step.newKey.clone(), step.newEpoch));
    report.rotatedNodeIds.push_back(step.nodeId);
    if (step.node.blob.has_value()) {
      report.blobReencryptionRequired.push_back(step.nodeId);
    }
  }
  Status rekeyed = rekeyShortcuts(rotated, removedType, removedId, report);
  if (rekeyed != Status::Ok) {
    return rekeyed;
  }
  return report;
}

// A shortcut carries its target's key wrapped under its parent, so a target that got a new key
// leaves its shortcuts on the old one. Wraps the new key and epoch for each, in the same operation.
Status Client::rekeyShortcuts(const std::map<std::string, std::pair<SymmetricKey, uint32_t>>& rotated,
                              const std::string& removedType, const std::string& removedId,
                              RotationReport& report) {
  for (const auto& [targetId, rotatedKey] : rotated) {
    for (const std::string& shortcutId : database_->shortcutsTo(targetId)) {
      Status rekeyed = rekeyShortcut(shortcutId, rotatedKey, rotated, removedType, removedId);
      if (rekeyed != Status::Ok) {
        return rekeyed;
      }
      if (rotated.find(shortcutId) == rotated.end()) {
        report.rotatedNodeIds.push_back(shortcutId);
      }
    }
  }
  return Status::Ok;
}

Status Client::rekeyShortcut(const std::string& shortcutId, const std::pair<SymmetricKey, uint32_t>& targetKey,
                             const std::map<std::string, std::pair<SymmetricKey, uint32_t>>& rotated,
                             const std::string& removedType, const std::string& removedId) {
  const Node* shortcut = database_->findNode(shortcutId);
  if (shortcut->deleted) {
    return Status::Ok;
  }
  // Only shortcuts whose parent key this client holds can be re-wrapped here.
  Result<RotationStep> step = planNodeRotation(*shortcut, removedType, removedId);
  if (step.status() == Status::NotFound) {
    return Status::Ok;
  }
  if (!step.ok()) {
    return step.status();
  }
  step.value().newKey = targetKey.first.clone();
  step.value().newEpoch = targetKey.second;
  SymmetricKey parentKey;
  uint32_t parentEpoch = 0;
  Status parentStatus = parentForStep(step.value(), rotated, parentKey, parentEpoch);
  if (parentStatus == Status::NotFound) {
    return Status::Ok;
  }
  if (parentStatus != Status::Ok) {
    return parentStatus;
  }
  return applyRotationStep(step.value(), &parentKey, parentEpoch);
}

Status Client::parentForStep(const RotationStep& step,
                             const std::map<std::string, std::pair<SymmetricKey, uint32_t>>& rotated,
                             SymmetricKey& parentKey, uint32_t& parentEpoch) {
  if (!step.node.parentId.has_value()) {
    return Status::Ok;
  }
  auto already = rotated.find(*step.node.parentId);
  if (already != rotated.end()) {
    parentKey = already->second.first.clone();
    parentEpoch = already->second.second;
    return Status::Ok;
  }
  const Node* parent = database_->findNode(*step.node.parentId);
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
  Result<RotationReport> report = rotateSubtree(nodeId, principalType, principalId);
  if (!report.ok()) {
    return report;
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
  Result<RotationReport> report = rotateSubtree(nodeId, "", "");
  if (!report.ok()) {
    return report;
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
