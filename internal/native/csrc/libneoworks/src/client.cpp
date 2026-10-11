#include "client.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>

#include "timeutil.hpp"

namespace nw {

namespace {

constexpr int kMaxAncestorWalk = 64;

}  // namespace

std::string Client::nowText() const { return formatRfc3339Utc(nowSeconds()); }

int64_t Client::nowSeconds() const {
  if (clock_) {
    return clock_();
  }
  return currentUnixSeconds();
}

NodeLookup Client::nodeLookup() const {
  return [this](const std::string& nodeId) { return database_->findNode(nodeId); };
}

namespace {

ShortcutLookup shortcutLookupOver(const LocalDatabase& database) {
  return [&database](const std::string& targetId) {
    std::vector<const Node*> shortcuts;
    for (const std::string& shortcutId : database.shortcutsTo(targetId)) {
      shortcuts.push_back(database.findNode(shortcutId));
    }
    return shortcuts;
  };
}

}  // namespace

std::unique_ptr<Client> Client::forInstall(Install install, std::unique_ptr<LocalDatabase> database) {
  std::unique_ptr<Client> client(new Client());
  client->signer_.authorType = "install";
  client->signer_.authorId = install.installId;
  client->signer_.signSecret = SecretBytes(install.signSecret.view());
  client->encPub_ = install.encPub;
  client->encSecret_ = SecretBytes(install.encSecret.view());
  client->signPub_ = install.signPub;
  client->database_ = std::move(database);
  client->keyring_.setShortcutLookup(shortcutLookupOver(*client->database_));
  client->restoreKeysFromDatabase();
  return client;
}

std::unique_ptr<Client> Client::forAccount(Account account, std::unique_ptr<LocalDatabase> database) {
  std::unique_ptr<Client> client(new Client());
  client->signer_.authorType = "user";
  client->signer_.authorId = account.userId();
  client->signer_.signSecret = SecretBytes(account.signSecret().view());
  client->encPub_ = Bytes(account.encPub().begin(), account.encPub().end());
  client->encSecret_ = SecretBytes(account.encSecret().view());
  client->signPub_ = Bytes(account.signPub().begin(), account.signPub().end());
  client->database_ = std::move(database);
  client->keyring_.setShortcutLookup(shortcutLookupOver(*client->database_));
  PinnedIdentity ownPin;
  ownPin.identity = account.publicIdentity();
  ownPin.userVerified = true;
  ownPin.pinnedAt = client->nowText();
  client->database_->putPin(ownPin);
  client->account_ = std::move(account);
  client->restoreKeysFromDatabase();
  return client;
}

namespace {

bool isNewerCertificate(const DelegationCertificate& candidate, const DelegationCertificate& current) {
  if (candidate.issuedAt != current.issuedAt) {
    return candidate.issuedAt > current.issuedAt;
  }
  return candidate.certId > current.certId;
}

}  // namespace

Status Client::restoreKeysFromDatabase() {
  for (const AccessGrant& grant : database_->allGrants()) {
    bool addressedToMe = grant.principalType == signer_.authorType && grant.principalId == signer_.authorId;
    if (addressedToMe && !grant.revokedAt.has_value()) {
      keyring_.addGrant(grant, encPub_, encSecret_.view());
    }
  }
  restoreNewestCertificate();
  return Status::Ok;
}

// An install that consented again holds several certificates; the newest one governs.
void Client::restoreNewestCertificate() {
  const StoredCertificate* newest = nullptr;
  std::vector<StoredCertificate> stored = database_->allCertificates();
  for (const StoredCertificate& candidate : stored) {
    if (candidate.certificate.installId != signer_.authorId) {
      continue;
    }
    if (newest == nullptr || isNewerCertificate(candidate.certificate, newest->certificate)) {
      newest = &candidate;
    }
  }
  if (newest == nullptr) {
    return;
  }
  certificate_ = newest->certificate;
  signer_.certId = newest->certificate.certId;
}

Status Client::storeCertificate(const Bytes& certificateBytes, const Bytes& signature) {
  Result<DelegationCertificate> hint = parseTrustedCertificate(certificateBytes);
  if (!hint.ok()) {
    return hint.status();
  }
  const PinnedIdentity* issuer = database_->findPin(hint.value().userId);
  if (issuer == nullptr) {
    return Status::NotFound;
  }
  Result<DelegationCertificate> verified = Status::Malformed;
  if (hint.value().renewalCertId.has_value()) {
    verified = verifyRenewedFromStore(hint.value(), certificateBytes, signature);
  } else {
    verified = verifyCertificateUnderKeys(issuer->verificationKeys(), certificateBytes, signature, std::nullopt);
  }
  if (!verified.ok()) {
    return verified.status();
  }
  return database_->putCertificate(StoredCertificate{verified.take(), certificateBytes, signature});
}

// NotFound: the renewal certificate or the origin has not been fetched yet.
Result<DelegationCertificate> Client::verifyRenewedFromStore(const DelegationCertificate& hint, const Bytes& certificateBytes,
                                                             const Bytes& signature) const {
  const StoredRenewalCertificate* renewal = database_->findRenewalCertificate(*hint.renewalCertId);
  const StoredCertificate* origin = database_->findCertificate(*hint.originCertId);
  if (renewal == nullptr || origin == nullptr) {
    return Status::NotFound;
  }
  return verifyRenewedCertificate(renewal->renewal, origin->certificate, certificateBytes, signature, std::nullopt);
}

Status Client::storeRenewalCertificate(const Bytes& renewalBytes, const Bytes& signature) {
  Result<RenewalCertificate> hint = parseTrustedRenewalCertificate(renewalBytes);
  if (!hint.ok()) {
    return hint.status();
  }
  const PinnedIdentity* issuer = database_->findPin(hint.value().userId);
  if (issuer == nullptr) {
    return Status::NotFound;
  }
  Result<RenewalCertificate> verified =
      verifyRenewalCertificateUnderKeys(issuer->verificationKeys(), renewalBytes, signature, std::nullopt);
  if (!verified.ok()) {
    return verified.status();
  }
  return database_->putRenewalCertificate(StoredRenewalCertificate{verified.take(), renewalBytes, signature});
}

namespace {

struct GrantBundle {
  Bytes certificate;
  Bytes signature;
  std::vector<AccessGrant> grants;
};

Result<GrantBundle> parseGrantBundle(const Json& json) {
  std::optional<Bytes> certificate = readBytes(json, "certificate");
  std::optional<Bytes> signature = readBytes(json, "certificateSignature");
  const Json* grantsJson = readArray(json, "grants");
  if (!certificate || !signature || grantsJson == nullptr) {
    return Status::Malformed;
  }
  GrantBundle bundle{std::move(*certificate), std::move(*signature), {}};
  for (const Json& entry : *grantsJson) {
    Result<AccessGrant> grant = grantFromJson(entry);
    if (!grant.ok()) {
      return grant.status();
    }
    bundle.grants.push_back(grant.take());
  }
  return bundle;
}

struct VerifiedBundleCertificate {
  DelegationCertificate certificate;
  std::optional<StoredRenewalCertificate> renewal;
};

// An identity-signed certificate verifies against the owner. A renewed one needs the renewal
// certificate that came with the bundle and the identity-signed origin the install already holds.
Result<VerifiedBundleCertificate> verifyBundleCertificate(const LocalDatabase& database,
                                                          const std::vector<IdentityVersion>& ownerKeys,
                                                          const Json& neoworksGrant, const GrantBundle& bundle,
                                                          int64_t now) {
  Result<DelegationCertificate> hint = parseTrustedCertificate(bundle.certificate);
  if (!hint.ok()) {
    return hint.status();
  }
  if (!hint.value().renewalCertId.has_value()) {
    Result<DelegationCertificate> verified = verifyCertificateUnderKeys(ownerKeys, bundle.certificate, bundle.signature, now);
    if (!verified.ok()) {
      return verified.status();
    }
    return VerifiedBundleCertificate{verified.take(), std::nullopt};
  }
  std::optional<Bytes> renewalBytes = readBytes(neoworksGrant, "renewalCertificate");
  std::optional<Bytes> renewalSignature = readBytes(neoworksGrant, "renewalCertificateSignature");
  const StoredCertificate* origin = database.findCertificate(*hint.value().originCertId);
  if (!renewalBytes || !renewalSignature) {
    return Status::Malformed;
  }
  if (origin == nullptr) {
    return Status::NotFound;
  }
  Result<RenewalCertificate> renewal = verifyRenewalCertificateUnderKeys(ownerKeys, *renewalBytes, *renewalSignature, now);
  if (!renewal.ok()) {
    return renewal.status();
  }
  Result<DelegationCertificate> verified = verifyRenewedCertificate(renewal.value(), origin->certificate,
                                                                    bundle.certificate, bundle.signature, now);
  if (!verified.ok()) {
    return verified.status();
  }
  StoredRenewalCertificate stored{renewal.take(), std::move(*renewalBytes), std::move(*renewalSignature)};
  return VerifiedBundleCertificate{verified.take(), std::move(stored)};
}

}  // namespace

Status Client::acceptGrantBundle(const Json& neoworksGrant, const PublicIdentity& ownerIdentity,
                                 const std::vector<IdentityVersion>& ownerHistory) {
  if (signer_.authorType != "install") {
    return Status::InvalidState;
  }
  Status identityStatus = verifyPublicIdentity(ownerIdentity);
  if (identityStatus != Status::Ok) {
    return identityStatus;
  }
  if (checkPin(ownerIdentity, ownerHistory) == PinState::Changed) {
    return Status::Conflict;
  }
  if (!ownerHistory.empty()) {
    Status chained = verifyHistoryEndsAt(ownerIdentity, ownerHistory);
    if (chained != Status::Ok) {
      return chained;
    }
  }
  PinnedIdentity candidate;
  candidate.identity = ownerIdentity;
  candidate.history = ownerHistory;
  Result<GrantBundle> bundle = parseGrantBundle(neoworksGrant);
  if (!bundle.ok()) {
    return bundle.status();
  }
  Result<VerifiedBundleCertificate> checked =
      verifyBundleCertificate(*database_, candidate.verificationKeys(), neoworksGrant, bundle.value(), nowSeconds());
  if (!checked.ok()) {
    return checked.status();
  }
  const DelegationCertificate& verified = checked.value().certificate;
  bool boundToMe = verified.installId == signer_.authorId && verified.installEncPub == encPub_ &&
                   verified.installSignPub == signPub_ && verified.userId == ownerIdentity.userId;
  if (!boundToMe) {
    return Status::AuthenticationFailed;
  }
  for (const AccessGrant& grant : bundle.value().grants) {
    bool addressedToMe = grant.principalType == "install" && grant.principalId == signer_.authorId;
    // The grant's signature covers its access log entry; it is verified once the node's chain
    // is pulled. Until then the sealed key only works if the owner really sealed it to us.
    bool grantedByOwner = grant.grantedByType == "user" && grant.grantedById == ownerIdentity.userId;
    if (!addressedToMe || !grantedByOwner) {
      return Status::AuthenticationFailed;
    }
  }
  Status pinned = pinIdentity(ownerIdentity, ownerHistory);
  if (pinned != Status::Ok) {
    return pinned;
  }
  if (checked.value().renewal.has_value()) {
    Status renewalStored = database_->putRenewalCertificate(*checked.value().renewal);
    if (renewalStored != Status::Ok) {
      return renewalStored;
    }
  }
  Status stored = database_->putCertificate(
      StoredCertificate{verified, bundle.value().certificate, bundle.value().signature});
  if (stored != Status::Ok) {
    return stored;
  }
  certificate_ = verified;
  signer_.certId = verified.certId;
  for (const AccessGrant& grant : bundle.value().grants) {
    database_->putGrant(grant);
    keyring_.addGrant(grant, encPub_, encSecret_.view());
  }
  return Status::Ok;
}

int Client::rankOnNode(const Node& node) const {
  int bestRank = 0;
  if (signer_.authorType == "user" && node.ownerId == signer_.authorId) {
    bestRank = roleRank("write");
  }
  for (const AccessGrant& grant : database_->grantsForNode(node.id)) {
    bool mine = grant.principalType == signer_.authorType && grant.principalId == signer_.authorId;
    bool wholeNode = !grant.facets.has_value();
    if (!mine || !wholeNode || grant.revokedAt.has_value()) {
      continue;
    }
    bestRank = std::max(bestRank, roleRank(grant.role));
  }
  return bestRank;
}

int Client::inheritedRank(const Node& node) const {
  int bestRank = 0;
  const Node* cursor = &node;
  for (int step = 0; step < kMaxAncestorWalk && cursor != nullptr; ++step) {
    bestRank = std::max(bestRank, rankOnNode(*cursor));
    if (!cursor->parentId.has_value()) {
      break;
    }
    cursor = database_->findNode(*cursor->parentId);
  }
  return bestRank;
}

int Client::rankThroughShortcuts(const Node& node) const {
  int bestRank = 0;
  for (const std::string& shortcutId : database_->shortcutsTo(node.id)) {
    const Node* shortcut = database_->findNode(shortcutId);
    if (shortcut->deleted || shortcut->collection != node.collection) {
      continue;
    }
    int granted = std::min(inheritedRank(*shortcut), roleRank(*shortcut->targetRole));
    bestRank = std::max(bestRank, granted);
  }
  return bestRank;
}

int Client::capByScopes(int rank, const Node& node) const {
  if (!certificate_.has_value()) {
    return rank;
  }
  bool mayWrite = certificateAllows(*certificate_, node.collection + ":write");
  bool mayRead = certificateAllows(*certificate_, node.collection + ":read");
  if (mayWrite) {
    return rank;
  }
  if (mayRead) {
    return std::min(rank, roleRank("read"));
  }
  return 0;
}

std::string Client::effectiveRole(const std::string& nodeId) const {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr) {
    return std::string();
  }
  int rank = capByScopes(std::max(inheritedRank(*node), rankThroughShortcuts(*node)), *node);
  if (rank == roleRank("write")) {
    return "write";
  }
  if (rank == roleRank("read")) {
    return "read";
  }
  return std::string();
}

Result<SymmetricKey> Client::resolveNodeKey(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr) {
    return Status::NotFound;
  }
  return keyring_.resolveNodeKey(*node, nodeLookup());
}

Status Client::signAndStore(Node& node) {
  node.authorType = signer_.authorType;
  node.authorId = signer_.authorId;
  node.certId = signer_.certId;
  Status signStatus = signNodeWrite(signer_.signSecret.view(), node);
  if (signStatus != Status::Ok) {
    return signStatus;
  }
  return database_->putNode(node, true);
}

Status Client::attachToParent(Node& node, const SymmetricKey& nodeKey) {
  const Node* parent = database_->findNode(*node.parentId);
  if (parent == nullptr || parent->collection != node.collection || parent->deleted) {
    return Status::NotFound;
  }
  if (roleRank(effectiveRole(parent->id)) < roleRank("write")) {
    return Status::Forbidden;
  }
  Result<SymmetricKey> parentKey = keyring_.resolveNodeKey(*parent, nodeLookup());
  if (!parentKey.ok()) {
    return parentKey.status();
  }
  node.ownerId = parent->ownerId;
  node.wrappedKey = wrapNodeKey(parentKey.value(), nodeKey, node.id, node.parentId, node.epoch, parent->epoch);
  return Status::Ok;
}

Status Client::createOwnerGrant(const Node& root, const SymmetricKey& nodeKey) {
  GrantRequest request;
  request.nodeId = root.id;
  request.principalType = "user";
  request.principalId = signer_.authorId;
  request.role = "write";
  request.epoch = root.epoch;
  request.principalEncPub = encPub_;
  request.grantedByType = "user";
  request.grantedById = signer_.authorId;
  request.createdAt = nowText();
  Result<AccessGrant> grant = createGrant(request, nodeKey);
  if (!grant.ok()) {
    return grant.status();
  }
  database_->putGrant(grant.value());
  return queueGrant(grant.value());
}

Status Client::queueGrant(const AccessGrant& grant) {
  Json operation = Json::object();
  operation["op"] = "grant";
  operation["nodeId"] = grant.nodeId;
  operation["grant"] = grantToJson(grant);
  return database_->putOutboxOperation(nextOutboxId(), operation);
}

std::string Client::nextOutboxId() {
  int64_t microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
  lastOutboxStamp_ = std::max(lastOutboxStamp_ + 1, microseconds);
  char prefix[32];
  static_cast<void>(std::snprintf(prefix, sizeof(prefix), "%020lld-", static_cast<long long>(lastOutboxStamp_)));
  return std::string(prefix) + newUuid();
}

}  // namespace nw
