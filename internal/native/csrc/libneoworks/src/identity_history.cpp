#include "identity_history.hpp"

#include "timeutil.hpp"
#include "tlv.hpp"

namespace nw {

Bytes identityRotationMessage(std::string_view userId, uint32_t version, ByteView signPub, ByteView encPub) {
  return TlvWriter("nw-identity-rotation-v1").text(userId).u32(version).bytes(signPub).bytes(encPub).finish();
}

Result<Bytes> signIdentityRotation(ByteView previousSignSecret, std::string_view userId, uint32_t version,
                                   ByteView signPub, ByteView encPub) {
  return sign(previousSignSecret, identityRotationMessage(userId, version, signPub, encPub));
}

Status verifyIdentityHistory(const std::string& userId, const std::vector<IdentityVersion>& versions) {
  if (versions.empty()) {
    return Status::Malformed;
  }
  for (size_t index = 0; index < versions.size(); ++index) {
    const IdentityVersion& current = versions[index];
    bool wellFormed = current.version == index + 1 && current.signPub.size() == kPublicKeyBytes &&
                      current.encPub.size() == kPublicKeyBytes;
    if (!wellFormed) {
      return Status::Malformed;
    }
    if (index == 0) {
      continue;
    }
    Bytes message = identityRotationMessage(userId, current.version, current.signPub, current.encPub);
    bool linked = current.rotationSig.size() == kSignatureBytes &&
                  verifySignature(versions[index - 1].signPub, message, current.rotationSig);
    if (!linked) {
      return Status::AuthenticationFailed;
    }
  }
  return Status::Ok;
}

Status verifyHistoryEndsAt(const PublicIdentity& identity, const std::vector<IdentityVersion>& history) {
  Status linked = verifyIdentityHistory(identity.userId, history);
  if (linked != Status::Ok) {
    return linked;
  }
  bool endsAtIdentity = history.back().signPub == identity.signPub && history.back().encPub == identity.encPub;
  if (!endsAtIdentity) {
    return Status::AuthenticationFailed;
  }
  return Status::Ok;
}

Json identityVersionToJson(const IdentityVersion& version) {
  Json json = Json::object();
  json["version"] = version.version;
  json["signPub"] = bytesToJson(version.signPub);
  json["encPub"] = bytesToJson(version.encPub);
  if (!version.rotationSig.empty()) {
    json["rotationSig"] = bytesToJson(version.rotationSig);
  }
  json["createdAt"] = version.createdAt;
  if (version.retiredAt.has_value()) {
    json["retiredAt"] = *version.retiredAt;
  }
  return json;
}

Result<IdentityVersion> identityVersionFromJson(const Json& json) {
  std::optional<uint64_t> version = readUnsigned(json, "version");
  std::optional<Bytes> signPub = readBytes(json, "signPub");
  std::optional<Bytes> encPub = readBytes(json, "encPub");
  bool wellFormed = true;
  std::optional<Bytes> rotationSig = readOptionalBytes(json, "rotationSig", wellFormed);
  std::optional<std::string> retiredAt = readOptionalString(json, "retiredAt", wellFormed);
  if (!version || !signPub || !encPub || !wellFormed || *version > UINT32_MAX) {
    return Status::Malformed;
  }
  IdentityVersion parsed;
  parsed.version = static_cast<uint32_t>(*version);
  parsed.signPub = std::move(*signPub);
  parsed.encPub = std::move(*encPub);
  if (rotationSig.has_value()) {
    parsed.rotationSig = std::move(*rotationSig);
  }
  std::optional<std::string> createdAt = readString(json, "createdAt");
  if (createdAt.has_value()) {
    parsed.createdAt = std::move(*createdAt);
  }
  parsed.retiredAt = std::move(retiredAt);
  return parsed;
}

Result<std::vector<IdentityVersion>> identityHistoryFromJson(const Json& json) {
  const Json* array = &json;
  if (json.is_object()) {
    array = readArray(json, "keys");
  }
  if (array == nullptr || !array->is_array()) {
    return Status::Malformed;
  }
  std::vector<IdentityVersion> versions;
  for (const Json& entry : *array) {
    Result<IdentityVersion> parsed = identityVersionFromJson(entry);
    if (!parsed.ok()) {
      return parsed.status();
    }
    versions.push_back(parsed.take());
  }
  return versions;
}

Json identityHistoryToJson(const std::vector<IdentityVersion>& versions) {
  Json array = Json::array();
  for (const IdentityVersion& version : versions) {
    array.push_back(identityVersionToJson(version));
  }
  return array;
}

bool keyValidAt(const IdentityVersion& version, const std::string& issuedAt) {
  if (!version.retiredAt.has_value()) {
    return true;
  }
  std::optional<int64_t> issued = parseRfc3339Utc(issuedAt);
  std::optional<int64_t> retired = parseRfc3339Utc(*version.retiredAt);
  if (!issued || !retired) {
    return false;
  }
  return *issued <= *retired;
}

}  // namespace nw
