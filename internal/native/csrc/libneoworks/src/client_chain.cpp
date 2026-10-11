#include <algorithm>
#include <map>

#include "client.hpp"

namespace nw {

namespace {

constexpr int kMaxAncestorSteps = 64;

std::string grantsPath(const std::string& nodeId) { return "/api/v1/nodes/" + nodeId + "/grants"; }

}  // namespace

int Client::inheritedRankFor(const Node& node, const std::string& principalType, const std::string& principalId,
                             const std::string& ownerId) const {
  int rank = 0;
  if (principalType == "user" && principalId == ownerId) {
    rank = roleRank("write");
  }
  const Node* cursor = &node;
  for (int step = 0; step < kMaxAncestorSteps && cursor->parentId.has_value(); ++step) {
    cursor = database_->findNode(*cursor->parentId);
    if (cursor == nullptr) {
      break;
    }
    ChainState state = replay(database_->chainOf(cursor->id));
    auto active = state.active.find(PrincipalKey(principalType, principalId));
    if (active != state.active.end() && !active->second.facets.has_value()) {
      rank = std::max(rank, roleRank(active->second.role));
    }
  }
  return rank;
}

AuthorityContext Client::authorityContextFor(const Node& node, const std::string& ownerId) const {
  AuthorityContext context;
  context.ownerId = ownerId;
  context.collection = node.collection;
  context.inheritedUserRank = [this, &node, ownerId](const std::string& userId) {
    return inheritedRankFor(node, "user", userId, ownerId);
  };
  context.inheritedInstallRank = [this, &node, ownerId](const std::string& installId) {
    return inheritedRankFor(node, "install", installId, ownerId);
  };
  context.certificateOf = [this](const std::string& certId) -> const DelegationCertificate* {
    const StoredCertificate* stored = database_->findCertificate(certId);
    if (stored == nullptr) {
      return nullptr;
    }
    return &stored->certificate;
  };
  context.userKeys = [this](const std::string& userId) -> std::vector<IdentityVersion> {
    const PinnedIdentity* pin = database_->findPin(userId);
    if (pin == nullptr) {
      return {};
    }
    return pin->verificationKeys();
  };
  return context;
}

Result<Client::SignedOperation> Client::signOutboxOperation(const Json& operation) {
  std::optional<std::string> kind = readString(operation, "op");
  std::optional<std::string> nodeId = readString(operation, "nodeId");
  if (!kind || !nodeId) {
    return Status::Malformed;
  }
  std::optional<LogHead> head = database_->headOf(*nodeId);
  SignedOperation signedOperation;
  if (*kind == "grant" && operation.contains("grant")) {
    Result<AccessGrant> grant = grantFromJson(operation.at("grant"));
    if (!grant.ok()) {
      return grant.status();
    }
    grant.value().grantedByType = signer_.authorType;
    grant.value().grantedById = signer_.authorId;
    signedOperation.entry = nextGrantEntry(grant.value(), head);
    signedOperation.method = "POST";
    signedOperation.path = grantsPath(*nodeId);
    signedOperation.grant = grant.take();
  } else if (*kind == "revoke") {
    std::optional<std::string> principalType = readString(operation, "principalType");
    std::optional<std::string> principalId = readString(operation, "principalId");
    if (!principalType || !principalId) {
      return Status::Malformed;
    }
    signedOperation.entry = nextRevokeEntry(*nodeId, *principalType, *principalId, signer_.authorId, head);
    signedOperation.entry.actorType = signer_.authorType;
    signedOperation.entry.certId = signer_.certId;
    signedOperation.method = "POST";
    signedOperation.path = grantsPath(*nodeId) + "/revoke";
  } else {
    return Status::Malformed;
  }
  Status signStatus = signEntry(signer_.signSecret.view(), signedOperation.entry);
  if (signStatus != Status::Ok) {
    return signStatus;
  }
  signedOperation.body = Json::object();
  if (signedOperation.grant.has_value()) {
    bindGrantToEntry(*signedOperation.grant, signedOperation.entry);
    signedOperation.body["grant"] = grantToJson(*signedOperation.grant);
  }
  signedOperation.body["entry"] = entryToJson(signedOperation.entry);
  return signedOperation;
}

Status Client::recordAppended(const SignedOperation& operation) {
  const std::string& nodeId = operation.entry.nodeId;
  if (checkLink(database_->headOf(nodeId), operation.entry) == Status::Ok) {
    Status appended = database_->appendChainEntries(nodeId, {operation.entry});
    if (appended != Status::Ok) {
      return appended;
    }
  }
  if (operation.grant.has_value()) {
    return database_->putGrant(*operation.grant);
  }
  return Status::Ok;
}

namespace {

bool signedByPinnedKey(const PinnedIdentity& pin, const AccessLogEntry& entry) {
  for (const IdentityVersion& key : pin.verificationKeys()) {
    if (verifyEntrySignature(key.signPub, entry)) {
      return true;
    }
  }
  return false;
}

}  // namespace

std::optional<Client::LookupNeed> Client::lookupNeededForEntry(const AccessLogEntry& entry) const {
  if (entry.actorType == "user" && database_->findPin(entry.actorId) == nullptr) {
    return LookupNeed{LookupNeed::Kind::Identity, entry.actorId};
  }
  if (entry.actorType == "user" && !signedByPinnedKey(*database_->findPin(entry.actorId), entry)) {
    // The user may have rotated their identity since the pin was taken.
    return LookupNeed{LookupNeed::Kind::Identity, entry.actorId, true};
  }
  bool needsCertificate = entry.certId.has_value() && database_->findCertificate(*entry.certId) == nullptr;
  if (needsCertificate) {
    return LookupNeed{LookupNeed::Kind::Certificate, *entry.certId};
  }
  return std::nullopt;
}

namespace {

Status integrityFailed(LocalDatabase& database, const std::string& nodeId, const char* reason) {
  database.recordIntegrityFailure(nodeId, reason);
  return Status::IntegrityFailure;
}

bool isRootBootstrap(const Node& node, const AccessLogEntry& entry) {
  return node.kind == "root" && entry.index == 0 && entry.action == "grant" && entry.principalType == "user" &&
         entry.principalId == entry.actorId && entry.actorType == "user" && node.ownerId == entry.actorId &&
         entry.role == "write";
}

// The newest identity version each user actor has signed with so far in the chain.
std::map<std::string, uint32_t> identityFloors(const std::vector<AccessLogEntry>& chain,
                                               const AuthorityContext& context) {
  std::map<std::string, uint32_t> floors;
  for (const AccessLogEntry& entry : chain) {
    uint32_t identityVersion = 0;
    bool verified = entry.actorType == "user" && verifyEntryActor(entry, context, identityVersion) == Status::Ok;
    if (verified && identityVersion > floors[entry.actorId]) {
      floors[entry.actorId] = identityVersion;
    }
  }
  return floors;
}

}  // namespace

Status Client::appendVerifiedEntries(const std::string& nodeId, std::vector<AccessLogEntry> entries) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr) {
    return Status::NotFound;
  }
  std::sort(entries.begin(), entries.end(),
            [](const AccessLogEntry& left, const AccessLogEntry& right) { return left.index < right.index; });
  std::vector<AccessLogEntry> chain = database_->chainOf(nodeId);
  std::vector<AccessLogEntry> accepted;
  std::optional<std::map<std::string, uint32_t>> floors;
  for (const AccessLogEntry& entry : entries) {
    if (entry.nodeId != nodeId) {
      return integrityFailed(*database_, nodeId, "entry for another node");
    }
    if (entry.index < chain.size()) {
      if (entryHash(chain[static_cast<size_t>(entry.index)]) != entryHash(entry)) {
        return integrityFailed(*database_, nodeId, "chain forked or rolled back");
      }
      continue;
    }
    std::optional<LogHead> head;
    if (!chain.empty()) {
      head = LogHead{chain.back().index, entryHash(chain.back())};
    }
    bool gap = entry.index != chain.size();
    if (gap) {
      return Status::ResyncRequired;
    }
    if (checkLink(head, entry) != Status::Ok) {
      return integrityFailed(*database_, nodeId, "entry does not extend the verified head");
    }
    std::string owner = trustedOwnerOf(*node);
    if (chain.empty() && isRootBootstrap(*node, entry)) {
      owner = entry.actorId;
    }
    AuthorityContext context = authorityContextFor(*node, owner);
    uint32_t identityVersion = 0;
    Status actor = verifyEntryActor(entry, context, identityVersion);
    if (actor == Status::NotFound) {
      return Status::NotFound;
    }
    if (actor != Status::Ok) {
      return integrityFailed(*database_, nodeId, "invalid entry signature");
    }
    if (!floors.has_value()) {
      floors = identityFloors(chain, context);
    }
    if (entry.actorType == "user" && identityVersion < (*floors)[entry.actorId]) {
      return integrityFailed(*database_, nodeId, "entry signed by an identity that was already replaced");
    }
    Status authority = checkAuthority(entry, replay(chain), context);
    if (authority == Status::NotFound) {
      return Status::NotFound;
    }
    if (authority != Status::Ok) {
      return integrityFailed(*database_, nodeId, "unauthorised access log entry");
    }
    if (entry.actorType == "user") {
      (*floors)[entry.actorId] = identityVersion;
    }
    chain.push_back(entry);
    accepted.push_back(entry);
  }
  if (accepted.empty()) {
    return Status::Ok;
  }
  return database_->appendChainEntries(nodeId, accepted);
}

Status Client::acceptPulledGrant(const AccessGrant& grant) {
  std::vector<AccessLogEntry> chain = database_->chainOf(grant.nodeId);
  if (grant.logIndex >= chain.size()) {
    return Status::NotFound;
  }
  if (!entryMatchesGrant(chain[static_cast<size_t>(grant.logIndex)], grant)) {
    return integrityFailed(*database_, grant.nodeId, "grant does not match its log entry");
  }
  Status stored = database_->putGrant(grant);
  if (stored != Status::Ok) {
    return stored;
  }
  bool addressedToMe = grant.principalType == signer_.authorType && grant.principalId == signer_.authorId;
  if (addressedToMe && !grant.revokedAt.has_value()) {
    keyring_.addGrant(grant, encPub_, encSecret_.view());
    indexPendingNodes();
  }
  return Status::Ok;
}

}  // namespace nw
