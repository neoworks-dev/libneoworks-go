#pragma once

#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "json.hpp"
#include "node.hpp"

namespace nw {

struct AccessGrant {
  std::string nodeId;
  std::string principalType;
  std::string principalId;
  std::string role;
  std::optional<std::vector<uint32_t>> facets;
  Bytes wrappedKeys;
  std::string grantedByType;
  std::string grantedById;
  std::optional<std::string> certId;
  // The moment the grant stops giving access, as YYYY-MM-DDTHH:MM:SSZ; part of the signed entry.
  std::optional<std::string> expiresAt;
  // The id of the grant this one was made from (see grantId), signed with it. A grant an install
  // received from its user's share of someone else's row names the user's grant; it ends with it.
  std::optional<std::string> via;
  // Signature of this grant's access log entry, and that entry's position in the node's chain.
  Bytes signature;
  uint64_t logIndex = 0;
  std::string createdAt;
  std::optional<std::string> revokedAt;
};

bool isValidRole(std::string_view role);
// A grant is identified by its row and its principal, since a row has at most one grant for each:
// "<nodeId>:<principalType>:<principalId>".
std::string grantId(const std::string& nodeId, const std::string& principalType, const std::string& principalId);
std::string grantId(const AccessGrant& grant);
bool isValidGrantId(std::string_view text);
// "read" < "write".
int roleRank(std::string_view role);

Json grantToJson(const AccessGrant& grant);
Result<AccessGrant> grantFromJson(const Json& json);

// No expiry, or a whole-second UTC instant (YYYY-MM-DDTHH:MM:SSZ) after now.
bool isFutureExpiry(const std::optional<std::string>& expiresAt);

std::string facetsCsv(const std::optional<std::vector<uint32_t>>& facets);

struct GrantRequest {
  std::string nodeId;
  std::string principalType;
  std::string principalId;
  std::string role;
  std::optional<std::vector<uint32_t>> facets;
  Bytes principalEncPub;
  std::string grantedByType;
  std::string grantedById;
  std::optional<std::string> certId;
  // Must be a whole-second UTC instant in the future.
  std::optional<std::string> expiresAt;
  // Set when the grant is made from the granter's own share of the row: the id of that grant.
  std::optional<std::string> via;
  std::string createdAt;
};

// Seals the node key (whole node) or the listed facet keys to the principal. The grant
// is unsigned: signing happens when its access log entry is appended (accesslog.hpp).
Result<AccessGrant> createGrant(const GrantRequest& request, const SymmetricKey& nodeKey);

struct OpenedGrant {
  std::optional<SymmetricKey> nodeKey;
  std::vector<std::pair<uint32_t, SymmetricKey>> facetKeys;
};

Result<OpenedGrant> openGrant(ByteView encPub, ByteView encSecret, const AccessGrant& grant);

}  // namespace nw
