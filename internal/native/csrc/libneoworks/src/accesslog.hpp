#pragma once

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "delegation.hpp"
#include "grant.hpp"

namespace nw {

// Per-node, append-only, hash-chained log of grants and revocations (contract
// amendment 1). Every entry is signed by a user identity key.
constexpr size_t kEntryHashBytes = 32;

struct AccessLogEntry {
  std::string nodeId;
  uint64_t index = 0;
  Bytes prevHash;
  std::string action;  // "grant" | "revoke"
  std::string principalType;
  std::string principalId;
  // Revokes carry an empty role and no facets.
  std::string role;
  std::optional<std::vector<uint32_t>> facets;
  // H(wrappedKeys) for grants, empty for revokes.
  Bytes wrappedKeysHash;
  std::string actorType;
  std::string actorId;
  // User actors granting to an install: that install's delegation certificate.
  // Install actors: their own certificate (required).
  std::optional<std::string> certId;
  // Grants only: when the grant stops giving access, YYYY-MM-DDTHH:MM:SSZ. The granter signs it,
  // so the server cannot extend it.
  std::optional<std::string> expiresAt;
  Bytes signature;
};

struct LogHead {
  uint64_t index = 0;
  Bytes entryHash;
};

Bytes zeroPrevHash();
Bytes entryBytes(const AccessLogEntry& entry);
Bytes entryHash(const AccessLogEntry& entry);
Status signEntry(ByteView actorSignSecret, AccessLogEntry& entry);
bool verifyEntrySignature(ByteView actorSignPub, const AccessLogEntry& entry);

Json entryToJson(const AccessLogEntry& entry);
Result<AccessLogEntry> entryFromJson(const Json& json);

// Unsigned entry that extends `head` (nullopt: first entry of the chain).
AccessLogEntry nextGrantEntry(const AccessGrant& grant, const std::optional<LogHead>& head);
AccessLogEntry nextRevokeEntry(const std::string& nodeId, const std::string& principalType,
                               const std::string& principalId, const std::string& actorId,
                               const std::optional<LogHead>& head);
// Applies the entry's position and signature to the grant it carries.
void bindGrantToEntry(AccessGrant& grant, const AccessLogEntry& entry);
// The grant is exactly what the signed entry commits to.
bool entryMatchesGrant(const AccessLogEntry& entry, const AccessGrant& grant);
// The revoke entry a revoked grant points at: same row, principal and index.
bool entryMatchesRevocation(const AccessLogEntry& entry, const AccessGrant& grant);

// Checks the entry extends `head` (index and prevHash).
Status checkLink(const std::optional<LogHead>& head, const AccessLogEntry& entry);

struct ActiveGrant {
  std::string role;
  std::optional<std::vector<uint32_t>> facets;
  std::string grantedBy;
  uint64_t index = 0;
};

using PrincipalKey = std::pair<std::string, std::string>;

// Who holds access after replaying a chain.
struct ChainState {
  std::map<PrincipalKey, ActiveGrant> active;
};
void applyEntry(ChainState& state, const AccessLogEntry& entry);
ChainState replay(const std::vector<AccessLogEntry>& entries);

struct AuthorityContext {
  std::string ownerId;
  std::string collection;
  // Role rank of a user / an install through ancestors of this node (0 when none).
  std::function<int(const std::string& userId)> inheritedUserRank;
  std::function<int(const std::string& installId)> inheritedInstallRank;
  std::function<const DelegationCertificate*(const std::string& certId)> certificateOf;
  // Identity keys of a user, newest first; empty when the user is not pinned. A legacy pin
  // without history yields one key with version 0.
  std::function<std::vector<IdentityVersion>(const std::string& userId)> userKeys;
};

// Signature of the entry by its actor: the user identity key, or the install key from
// the actor's certificate (which must name the actor and be required).
// `identityVersion` receives the identity version a user actor's signature verified under (0 for installs).
Status verifyEntryActor(const AccessLogEntry& entry, const AuthorityContext& context, uint32_t& identityVersion);
Status verifyEntryActor(const AccessLogEntry& entry, const AuthorityContext& context);

// Who may do what:
//  - grant to another user: the node's owner, or an install acting for the owner whose
//    certificate carries `<collection>:share` and whose own role is at least the granted role;
//  - grant to an install: the install's own user, at most their own role;
//  - revoke: the owner (or such an install) anyone; a user their own installs and their own grant.
// Neither certificate expiry nor a grant's expiresAt is checked: the server enforces both.
Status checkAuthority(const AccessLogEntry& entry, const ChainState& stateBefore, const AuthorityContext& context);

}  // namespace nw
