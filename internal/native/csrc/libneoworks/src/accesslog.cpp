#include "accesslog.hpp"

#include <algorithm>

#include "tlv.hpp"

namespace nw {

Bytes zeroPrevHash() { return Bytes(kEntryHashBytes, 0); }

Bytes entryBytes(const AccessLogEntry& entry) {
  return TlvWriter("nw-access-entry-v2")
      .text(entry.nodeId)
      .u64(entry.index)
      .bytes(entry.prevHash)
      .text(entry.action)
      .text(entry.principalType)
      .text(entry.principalId)
      .text(entry.role)
      .text(facetsCsv(entry.facets))
      .bytes(entry.wrappedKeysHash)
      .text(entry.actorType)
      .text(entry.actorId)
      .optionalText(entry.certId)
      .finish();
}

Bytes entryHash(const AccessLogEntry& entry) { return hash(entryBytes(entry)); }

Status signEntry(ByteView actorSignSecret, AccessLogEntry& entry) {
  Result<Bytes> signature = sign(actorSignSecret, entryBytes(entry));
  if (!signature.ok()) {
    return signature.status();
  }
  entry.signature = signature.take();
  return Status::Ok;
}

bool verifyEntrySignature(ByteView actorSignPub, const AccessLogEntry& entry) {
  return verifySignature(actorSignPub, entryBytes(entry), entry.signature);
}

Json entryToJson(const AccessLogEntry& entry) {
  Json json = Json::object();
  json["nodeId"] = entry.nodeId;
  json["index"] = entry.index;
  json["prevHash"] = bytesToJson(entry.prevHash);
  json["action"] = entry.action;
  json["principalType"] = entry.principalType;
  json["principalId"] = entry.principalId;
  json["role"] = entry.role;
  json["facets"] = Json(nullptr);
  if (entry.facets.has_value()) {
    json["facets"] = *entry.facets;
  }
  json["wrappedKeysHash"] = bytesToJson(entry.wrappedKeysHash);
  json["actorType"] = entry.actorType;
  json["actorId"] = entry.actorId;
  json["certId"] = Json(nullptr);
  if (entry.certId.has_value()) {
    json["certId"] = *entry.certId;
  }
  json["signature"] = bytesToJson(entry.signature);
  return json;
}

namespace {

Result<std::optional<std::vector<uint32_t>>> readFacets(const Json& json) {
  if (!json.contains("facets") || json.at("facets").is_null()) {
    return std::optional<std::vector<uint32_t>>();
  }
  if (!json.at("facets").is_array()) {
    return Status::Malformed;
  }
  std::vector<uint32_t> facets;
  for (const Json& facet : json.at("facets")) {
    if (!facet.is_number_unsigned() || facet.get<uint64_t>() > UINT32_MAX) {
      return Status::Malformed;
    }
    facets.push_back(facet.get<uint32_t>());
  }
  return std::optional<std::vector<uint32_t>>(std::move(facets));
}

struct EntryScalars {
  std::optional<std::string> nodeId, action, principalType, principalId, role, actorType, actorId;
  std::optional<uint64_t> index;
  std::optional<Bytes> prevHash, wrappedKeysHash, signature;

  bool complete() const {
    return nodeId && action && principalType && principalId && role && actorType && actorId && index &&
           prevHash && wrappedKeysHash && signature;
  }
};

EntryScalars readEntryScalars(const Json& json) {
  EntryScalars scalars;
  scalars.nodeId = readString(json, "nodeId");
  scalars.action = readString(json, "action");
  scalars.principalType = readString(json, "principalType");
  scalars.principalId = readString(json, "principalId");
  scalars.role = readString(json, "role");
  scalars.actorType = readString(json, "actorType");
  scalars.actorId = readString(json, "actorId");
  scalars.index = readUnsigned(json, "index");
  scalars.prevHash = readBytes(json, "prevHash");
  scalars.wrappedKeysHash = readBytes(json, "wrappedKeysHash");
  scalars.signature = readBytes(json, "signature");
  return scalars;
}

bool hasValidEntryShape(const EntryScalars& scalars) {
  bool actionValid = *scalars.action == "grant" || *scalars.action == "revoke";
  return actionValid && isLowercaseUuid(*scalars.nodeId) && isValidPrincipalType(*scalars.principalType) &&
         scalars.prevHash->size() == kEntryHashBytes;
}

}  // namespace

Result<AccessLogEntry> entryFromJson(const Json& json) {
  EntryScalars scalars = readEntryScalars(json);
  if (!scalars.complete() || !hasValidEntryShape(scalars)) {
    return Status::Malformed;
  }
  Result<std::optional<std::vector<uint32_t>>> facets = readFacets(json);
  bool wellFormed = true;
  std::optional<std::string> certId = readOptionalString(json, "certId", wellFormed);
  if (!facets.ok() || !wellFormed) {
    return Status::Malformed;
  }
  AccessLogEntry entry;
  entry.nodeId = *scalars.nodeId;
  entry.index = *scalars.index;
  entry.prevHash = std::move(*scalars.prevHash);
  entry.action = *scalars.action;
  entry.principalType = *scalars.principalType;
  entry.principalId = *scalars.principalId;
  entry.role = *scalars.role;
  entry.facets = facets.take();
  entry.wrappedKeysHash = std::move(*scalars.wrappedKeysHash);
  entry.actorType = *scalars.actorType;
  entry.actorId = *scalars.actorId;
  entry.certId = certId;
  entry.signature = std::move(*scalars.signature);
  return entry;
}

namespace {

void chainOnto(AccessLogEntry& entry, const std::optional<LogHead>& head) {
  if (!head.has_value()) {
    entry.index = 0;
    entry.prevHash = zeroPrevHash();
    return;
  }
  entry.index = head->index + 1;
  entry.prevHash = head->entryHash;
}

}  // namespace

AccessLogEntry nextGrantEntry(const AccessGrant& grant, const std::optional<LogHead>& head) {
  AccessLogEntry entry;
  entry.nodeId = grant.nodeId;
  entry.action = "grant";
  entry.principalType = grant.principalType;
  entry.principalId = grant.principalId;
  entry.role = grant.role;
  entry.facets = grant.facets;
  entry.wrappedKeysHash = hash(grant.wrappedKeys);
  entry.actorType = grant.grantedByType;
  entry.actorId = grant.grantedById;
  entry.certId = grant.certId;
  chainOnto(entry, head);
  return entry;
}

AccessLogEntry nextRevokeEntry(const std::string& nodeId, const std::string& principalType,
                               const std::string& principalId, const std::string& actorId,
                               const std::optional<LogHead>& head) {
  AccessLogEntry entry;
  entry.nodeId = nodeId;
  entry.action = "revoke";
  entry.principalType = principalType;
  entry.principalId = principalId;
  entry.actorType = "user";
  entry.actorId = actorId;
  chainOnto(entry, head);
  return entry;
}

void bindGrantToEntry(AccessGrant& grant, const AccessLogEntry& entry) {
  grant.logIndex = entry.index;
  grant.signature = entry.signature;
}

bool entryMatchesGrant(const AccessLogEntry& entry, const AccessGrant& grant) {
  return entry.action == "grant" && entry.nodeId == grant.nodeId && entry.index == grant.logIndex &&
         entry.principalType == grant.principalType && entry.principalId == grant.principalId &&
         entry.role == grant.role && entry.facets == grant.facets &&
         entry.wrappedKeysHash == hash(grant.wrappedKeys) && entry.actorType == grant.grantedByType &&
         entry.actorId == grant.grantedById && entry.certId == grant.certId && entry.signature == grant.signature;
}

bool entryMatchesRevocation(const AccessLogEntry& entry, const AccessGrant& grant) {
  return entry.action == "revoke" && entry.nodeId == grant.nodeId && entry.index == grant.logIndex &&
         entry.principalType == grant.principalType && entry.principalId == grant.principalId;
}

Status checkLink(const std::optional<LogHead>& head, const AccessLogEntry& entry) {
  if (!head.has_value()) {
    if (entry.index != 0 || entry.prevHash != zeroPrevHash()) {
      return Status::AuthenticationFailed;
    }
    return Status::Ok;
  }
  if (entry.index != head->index + 1 || entry.prevHash != head->entryHash) {
    return Status::AuthenticationFailed;
  }
  return Status::Ok;
}

void applyEntry(ChainState& state, const AccessLogEntry& entry) {
  PrincipalKey key(entry.principalType, entry.principalId);
  if (entry.action == "revoke") {
    state.active.erase(key);
    return;
  }
  state.active[key] = ActiveGrant{entry.role, entry.facets, entry.actorId, entry.index};
}

ChainState replay(const std::vector<AccessLogEntry>& entries) {
  ChainState state;
  for (const AccessLogEntry& entry : entries) {
    applyEntry(state, entry);
  }
  return state;
}

namespace {

int userWholeNodeRank(const std::string& userId, const ChainState& stateBefore, const AuthorityContext& context) {
  int rank = context.inheritedUserRank(userId);
  auto own = stateBefore.active.find(PrincipalKey("user", userId));
  if (own != stateBefore.active.end() && !own->second.facets.has_value()) {
    rank = std::max(rank, roleRank(own->second.role));
  }
  return rank;
}

int installWholeNodeRank(const std::string& installId, const ChainState& stateBefore, const AuthorityContext& context) {
  int rank = context.inheritedInstallRank(installId);
  auto own = stateBefore.active.find(PrincipalKey("install", installId));
  if (own != stateBefore.active.end() && !own->second.facets.has_value()) {
    rank = std::max(rank, roleRank(own->second.role));
  }
  return rank;
}

Status checkInstallGrant(const AccessLogEntry& entry, const ChainState& stateBefore, const AuthorityContext& context) {
  if (entry.actorType != "user" || !entry.certId.has_value()) {
    return Status::Forbidden;
  }
  const DelegationCertificate* certificate = context.certificateOf(*entry.certId);
  if (certificate == nullptr) {
    return Status::NotFound;
  }
  if (certificate->installId != entry.principalId || certificate->userId != entry.actorId) {
    return Status::Forbidden;
  }
  if (entry.actorId == context.ownerId) {
    return Status::Ok;
  }
  bool withinOwnRole = roleRank(entry.role) <= userWholeNodeRank(entry.actorId, stateBefore, context);
  if (!withinOwnRole || entry.facets.has_value()) {
    return Status::Forbidden;
  }
  return Status::Ok;
}

// An install acts for the owner: certificate user is the owner, it holds the share scope.
Status checkInstallActor(const AccessLogEntry& entry, const ChainState& stateBefore,
                         const AuthorityContext& context) {
  if (!entry.certId.has_value()) {
    return Status::Forbidden;
  }
  const DelegationCertificate* certificate = context.certificateOf(*entry.certId);
  if (certificate == nullptr) {
    return Status::NotFound;
  }
  bool actsForOwner = certificate->installId == entry.actorId && certificate->userId == context.ownerId &&
                      certificateAllows(*certificate, context.collection + ":share");
  if (!actsForOwner) {
    return Status::Forbidden;
  }
  if (entry.action == "revoke") {
    return Status::Ok;
  }
  bool grantsToUser = entry.principalType == "user" && isValidRole(entry.role);
  if (!grantsToUser || roleRank(entry.role) > installWholeNodeRank(entry.actorId, stateBefore, context)) {
    return Status::Forbidden;
  }
  return Status::Ok;
}

Status checkGrantAuthority(const AccessLogEntry& entry, const ChainState& stateBefore,
                           const AuthorityContext& context) {
  if (!isValidRole(entry.role)) {
    return Status::Forbidden;
  }
  if (entry.principalType == "user") {
    if (entry.actorId != context.ownerId) {
      return Status::Forbidden;
    }
    return Status::Ok;
  }
  return checkInstallGrant(entry, stateBefore, context);
}

Status checkRevokeAuthority(const AccessLogEntry& entry, const ChainState& stateBefore,
                            const AuthorityContext& context) {
  if (entry.actorId == context.ownerId) {
    return Status::Ok;
  }
  if (entry.principalType == "user") {
    if (entry.principalId == entry.actorId) {
      return Status::Ok;
    }
    return Status::Forbidden;
  }
  auto target = stateBefore.active.find(PrincipalKey(entry.principalType, entry.principalId));
  if (target != stateBefore.active.end() && target->second.grantedBy == entry.actorId) {
    return Status::Ok;
  }
  return Status::Forbidden;
}

}  // namespace

Status verifyEntryActor(const AccessLogEntry& entry, const AuthorityContext& context) {
  uint32_t identityVersion = 0;
  return verifyEntryActor(entry, context, identityVersion);
}

Status verifyEntryActor(const AccessLogEntry& entry, const AuthorityContext& context, uint32_t& identityVersion) {
  identityVersion = 0;
  if (entry.actorType == "user") {
    std::vector<IdentityVersion> keys = context.userKeys(entry.actorId);
    if (keys.empty()) {
      return Status::NotFound;
    }
    for (const IdentityVersion& key : keys) {
      if (verifyEntrySignature(key.signPub, entry)) {
        identityVersion = key.version;
        return Status::Ok;
      }
    }
    return Status::AuthenticationFailed;
  }
  if (entry.actorType != "install" || !entry.certId.has_value()) {
    return Status::Forbidden;
  }
  const DelegationCertificate* certificate = context.certificateOf(*entry.certId);
  if (certificate == nullptr) {
    return Status::NotFound;
  }
  if (certificate->installId != entry.actorId || !verifyEntrySignature(certificate->installSignPub, entry)) {
    return Status::AuthenticationFailed;
  }
  return Status::Ok;
}

Status checkAuthority(const AccessLogEntry& entry, const ChainState& stateBefore, const AuthorityContext& context) {
  if (entry.actorType == "install") {
    return checkInstallActor(entry, stateBefore, context);
  }
  if (entry.actorType != "user") {
    return Status::Forbidden;
  }
  if (entry.action == "grant") {
    return checkGrantAuthority(entry, stateBefore, context);
  }
  return checkRevokeAuthority(entry, stateBefore, context);
}

}  // namespace nw
