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
  // Signature of this grant's access log entry, and that entry's position in the node's chain.
  Bytes signature;
  uint64_t logIndex = 0;
  std::string createdAt;
  std::optional<std::string> revokedAt;
};

bool isValidRole(std::string_view role);
// "read" < "write".
int roleRank(std::string_view role);

Json grantToJson(const AccessGrant& grant);
Result<AccessGrant> grantFromJson(const Json& json);

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
