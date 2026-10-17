#include <sodium.h>

#include <algorithm>

#include "client.hpp"
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
  grantRequest.principalEncPub = request.principalEncPub;
  grantRequest.grantedByType = signer_.authorType;
  grantRequest.grantedById = signer_.authorId;
  if (!certId.value().empty()) {
    grantRequest.certId = certId.value();
  }
  grantRequest.expiresAt = request.expiresAt;
  grantRequest.via = request.via;
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

std::optional<AccessGrant> Client::ownWholeGrantOn(const std::string& nodeId) const {
  for (const AccessGrant& grant : database_->grantsForNode(nodeId)) {
    bool mine = grant.principalType == signer_.authorType && grant.principalId == signer_.authorId;
    if (mine && !grant.facets.has_value() && !grant.revokedAt.has_value()) {
      return grant;
    }
  }
  return std::nullopt;
}

std::optional<AccessGrant> Client::ownGrantReaching(const Node& node) const {
  const Node* current = &node;
  for (int step = 0; step < 64 && current != nullptr; ++step) {
    std::optional<AccessGrant> grant = ownWholeGrantOn(current->id);
    if (grant.has_value() || !current->parentId.has_value()) {
      return grant;
    }
    current = database_->findNode(*current->parentId);
  }
  return std::nullopt;
}

Result<ShareRequest> Client::withSourceGrant(const Node& node, ShareRequest request) const {
  bool passesOnShare = request.principalType == "install" && signer_.authorType == "user" &&
                       trustedOwnerOf(node) != signer_.authorId;
  if (!passesOnShare || request.via.has_value()) {
    return request;
  }
  std::optional<AccessGrant> source = ownGrantReaching(node);
  if (!source.has_value()) {
    return Status::Forbidden;
  }
  request.via = grantId(*source);
  return request;
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
  Result<ShareRequest> sourced = withSourceGrant(*node, request);
  if (!sourced.ok()) {
    return sourced.status();
  }
  return grantNode(sourced.value());
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

Status Client::revokeAccess(const std::string& nodeId, const std::string& principalType,
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
  AccessGrant revoked = *target;
  revoked.revokedAt = nowText();
  Status stored = database_->putGrant(revoked);
  if (stored != Status::Ok) {
    return stored;
  }
  return queueRevocation(nodeId, principalType, principalId);
}

Result<std::string> Client::createLinkFragment(const std::string& nodeId,
                                               const std::optional<std::string>& expiresAt) {
  if (!isFutureExpiry(expiresAt)) {
    return Status::InvalidArgument;
  }
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
  ByteView keyView = nodeKey.value().view();
  Bytes fragment(keyView.begin(), keyView.end());
  std::string encoded = toBase64Url(fragment);
  sodium_memzero(fragment.data(), fragment.size());
  return encoded;
}

Status Client::recordLink(const std::string& nodeId, const std::string& linkId,
                          const std::optional<std::string>& expiresAt) {
  if (database_->findNode(nodeId) == nullptr) {
    return Status::NotFound;
  }
  return database_->putLink(LinkEntry{nodeId, linkId, nowText(), expiresAt});
}

std::vector<LinkRecord> Client::linksFor(const std::string& nodeId) const {
  std::vector<LinkRecord> records;
  for (const LinkEntry& entry : database_->linksForNode(nodeId)) {
    records.push_back(LinkRecord{entry.nodeId, entry.linkId, entry.createdAt, entry.expiresAt});
  }
  return records;
}

Status Client::revokeLink(const std::string& linkId) {
  const LinkEntry* link = database_->findLink(linkId);
  if (link == nullptr) {
    return Status::NotFound;
  }
  std::string nodeId = link->nodeId;
  const Node* linkedNode = database_->findNode(nodeId);
  if (linkedNode == nullptr || !canManageAccess(*linkedNode)) {
    return Status::Forbidden;
  }
  Json operation = Json::object();
  operation["op"] = "link-revoke";
  operation["nodeId"] = nodeId;
  operation["linkId"] = linkId;
  Status queued = database_->putOutboxOperation(nextOutboxId(), operation);
  if (queued != Status::Ok) {
    return queued;
  }
  return database_->removeLink(linkId);
}

}  // namespace nw
