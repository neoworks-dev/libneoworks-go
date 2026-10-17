#include "grant.hpp"

#include <algorithm>

#include "tlv.hpp"

namespace nw {

bool isValidRole(std::string_view role) { return roleRank(role) > 0; }

int roleRank(std::string_view role) {
  if (role == "read") {
    return 1;
  }
  if (role == "write") {
    return 2;
  }
  return 0;
}

std::string facetsCsv(const std::optional<std::vector<uint32_t>>& facets) {
  if (!facets.has_value()) {
    return std::string();
  }
  std::string csv;
  for (size_t index = 0; index < facets->size(); ++index) {
    if (index > 0) {
      csv += ",";
    }
    csv += std::to_string((*facets)[index]);
  }
  return csv;
}

Json grantToJson(const AccessGrant& grant) {
  Json json = Json::object();
  json["nodeId"] = grant.nodeId;
  json["principalType"] = grant.principalType;
  json["principalId"] = grant.principalId;
  json["role"] = grant.role;
  json["facets"] = Json(nullptr);
  if (grant.facets.has_value()) {
    json["facets"] = *grant.facets;
  }
  json["wrappedKeys"] = bytesToJson(grant.wrappedKeys);
  json["grantedByType"] = grant.grantedByType;
  json["grantedById"] = grant.grantedById;
  json["certId"] = Json(nullptr);
  if (grant.certId.has_value()) {
    json["certId"] = *grant.certId;
  }
  json["signature"] = bytesToJson(grant.signature);
  json["logIndex"] = grant.logIndex;
  json["createdAt"] = grant.createdAt;
  json["revokedAt"] = Json(nullptr);
  if (grant.revokedAt.has_value()) {
    json["revokedAt"] = *grant.revokedAt;
  }
  return json;
}

namespace {

Result<std::optional<std::vector<uint32_t>>> facetsFromJson(const Json& json) {
  if (!json.is_object() || !json.contains("facets") || json.at("facets").is_null()) {
    return std::optional<std::vector<uint32_t>>();
  }
  const Json& facetsJson = json.at("facets");
  if (!facetsJson.is_array()) {
    return Status::Malformed;
  }
  std::vector<uint32_t> facets;
  for (const Json& entry : facetsJson) {
    if (!entry.is_number_unsigned() || entry.get<uint64_t>() > UINT32_MAX) {
      return Status::Malformed;
    }
    facets.push_back(entry.get<uint32_t>());
  }
  return std::optional<std::vector<uint32_t>>(std::move(facets));
}

struct GrantScalars {
  std::optional<std::string> nodeId, principalType, principalId, role, grantedByType, grantedById, createdAt;
  std::optional<Bytes> wrappedKeys, signature;

  bool complete() const {
    return nodeId && principalType && principalId && role && grantedByType && grantedById && createdAt &&
           wrappedKeys && signature;
  }
};

GrantScalars readGrantScalars(const Json& json) {
  GrantScalars scalars;
  scalars.nodeId = readString(json, "nodeId");
  scalars.principalType = readString(json, "principalType");
  scalars.principalId = readString(json, "principalId");
  scalars.role = readString(json, "role");
  scalars.grantedByType = readString(json, "grantedByType");
  scalars.grantedById = readString(json, "grantedById");
  scalars.createdAt = readString(json, "createdAt");
  scalars.wrappedKeys = readBytes(json, "wrappedKeys");
  scalars.signature = readBytes(json, "signature");
  return scalars;
}

bool hasValidGrantIdentity(const GrantScalars& scalars) {
  return isLowercaseUuid(*scalars.nodeId) && isValidPrincipalType(*scalars.principalType) &&
         isValidPrincipalType(*scalars.grantedByType) && isValidRole(*scalars.role);
}

}  // namespace

Result<AccessGrant> grantFromJson(const Json& json) {
  GrantScalars scalars = readGrantScalars(json);
  if (!scalars.complete() || !hasValidGrantIdentity(scalars)) {
    return Status::Malformed;
  }
  Result<std::optional<std::vector<uint32_t>>> facets = facetsFromJson(json);
  if (!facets.ok()) {
    return facets.status();
  }
  bool wellFormed = true;
  AccessGrant grant;
  grant.certId = readOptionalString(json, "certId", wellFormed);
  grant.revokedAt = readOptionalString(json, "revokedAt", wellFormed);
  if (!wellFormed) {
    return Status::Malformed;
  }
  grant.nodeId = *scalars.nodeId;
  grant.principalType = *scalars.principalType;
  grant.principalId = *scalars.principalId;
  grant.role = *scalars.role;
  grant.facets = facets.take();
  grant.wrappedKeys = std::move(*scalars.wrappedKeys);
  grant.grantedByType = *scalars.grantedByType;
  grant.grantedById = *scalars.grantedById;
  grant.signature = std::move(*scalars.signature);
  grant.logIndex = readUnsigned(json, "logIndex").value_or(0);
  grant.createdAt = *scalars.createdAt;
  return grant;
}

namespace {

SecretBytes concatenateFacetKeys(const SymmetricKey& nodeKey, const std::vector<uint32_t>& facets) {
  SecretBytes joined(facets.size() * kKeyBytes);
  for (size_t index = 0; index < facets.size(); ++index) {
    SymmetricKey key = facetKey(nodeKey, facets[index]);
    std::copy(key.data(), key.data() + kKeyBytes, joined.data() + index * kKeyBytes);
  }
  return joined;
}

}  // namespace

Result<AccessGrant> createGrant(const GrantRequest& request, const SymmetricKey& nodeKey) {
  bool validRequest = isLowercaseUuid(request.nodeId) && isValidPrincipalType(request.principalType) &&
                      isValidPrincipalType(request.grantedByType) && isValidRole(request.role);
  if (!validRequest) {
    return Status::InvalidArgument;
  }
  AccessGrant grant;
  grant.nodeId = request.nodeId;
  grant.principalType = request.principalType;
  grant.principalId = request.principalId;
  grant.role = request.role;
  grant.facets = request.facets;
  grant.grantedByType = request.grantedByType;
  grant.grantedById = request.grantedById;
  grant.certId = request.certId;
  grant.createdAt = request.createdAt;

  Result<Bytes> sealed = Status::InvalidArgument;
  if (request.facets.has_value()) {
    sealed = seal(request.principalEncPub, concatenateFacetKeys(nodeKey, *request.facets).view());
  } else {
    sealed = seal(request.principalEncPub, nodeKey.view());
  }
  if (!sealed.ok()) {
    return sealed.status();
  }
  grant.wrappedKeys = sealed.take();
  return grant;
}

Result<OpenedGrant> openGrant(ByteView encPub, ByteView encSecret, const AccessGrant& grant) {
  Result<SecretBytes> opened = sealOpen(encPub, encSecret, grant.wrappedKeys);
  if (!opened.ok()) {
    return opened.status();
  }
  OpenedGrant result;
  if (!grant.facets.has_value()) {
    Result<SymmetricKey> nodeKey = SymmetricKey::fromBytes(opened.value().view());
    if (!nodeKey.ok()) {
      return nodeKey.status();
    }
    result.nodeKey = nodeKey.take();
    return result;
  }
  if (opened.value().size() != grant.facets->size() * kKeyBytes) {
    return Status::Malformed;
  }
  for (size_t index = 0; index < grant.facets->size(); ++index) {
    ByteView keyBytes = opened.value().view().subspan(index * kKeyBytes, kKeyBytes);
    result.facetKeys.emplace_back((*grant.facets)[index], SymmetricKey::fromBytes(keyBytes).take());
  }
  return result;
}

}  // namespace nw
