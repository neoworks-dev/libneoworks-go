#include "delegation.hpp"

#include <algorithm>

#include "tlv.hpp"
#include "timeutil.hpp"

namespace nw {

Bytes encodeCertificate(const DelegationCertificate& certificate) {
  Json json = Json::object();
  json["v"] = 1;
  json["certId"] = certificate.certId;
  json["userId"] = certificate.userId;
  json["installId"] = certificate.installId;
  json["clientId"] = certificate.clientId;
  json["installEncPub"] = bytesToJson(certificate.installEncPub);
  json["installSignPub"] = bytesToJson(certificate.installSignPub);
  json["scopes"] = certificate.scopes;
  json["issuedAt"] = certificate.issuedAt;
  json["expiresAt"] = certificate.expiresAt;
  if (certificate.originCertId.has_value() && certificate.renewalCertId.has_value()) {
    json["originCertId"] = *certificate.originCertId;
    json["renewalCertId"] = *certificate.renewalCertId;
  }
  return bytesOf(dumpCompact(json));
}

Bytes certificateSignatureMessage(ByteView certificateBytes) {
  return TlvWriter("nw-delegation-v1").bytes(certificateBytes).finish();
}

Result<Bytes> signCertificate(ByteView userSignSecret, ByteView certificateBytes) {
  return sign(userSignSecret, certificateSignatureMessage(certificateBytes));
}

namespace {

Result<std::vector<std::string>> scopesFromJson(const Json& json) {
  const Json* scopesJson = readArray(json, "scopes");
  if (scopesJson == nullptr) {
    return Status::Malformed;
  }
  std::vector<std::string> scopes;
  for (const Json& entry : *scopesJson) {
    if (!entry.is_string()) {
      return Status::Malformed;
    }
    scopes.push_back(entry.get<std::string>());
  }
  return scopes;
}

struct CertificateScalars {
  std::optional<std::string> certId, userId, installId, clientId, issuedAt, expiresAt;
  std::optional<Bytes> installEncPub, installSignPub;
  std::optional<uint64_t> version;

  bool complete() const {
    return certId && userId && installId && clientId && issuedAt && expiresAt && installEncPub &&
           installSignPub && version;
  }
};

CertificateScalars readCertificateScalars(const Json& json) {
  CertificateScalars scalars;
  scalars.version = readUnsigned(json, "v");
  scalars.certId = readString(json, "certId");
  scalars.userId = readString(json, "userId");
  scalars.installId = readString(json, "installId");
  scalars.clientId = readString(json, "clientId");
  scalars.issuedAt = readString(json, "issuedAt");
  scalars.expiresAt = readString(json, "expiresAt");
  scalars.installEncPub = readBytes(json, "installEncPub");
  scalars.installSignPub = readBytes(json, "installSignPub");
  return scalars;
}

bool hasValidCertificateIdentifiers(const CertificateScalars& scalars) {
  return isLowercaseUuid(*scalars.certId) && isLowercaseUuid(*scalars.userId) &&
         isLowercaseUuid(*scalars.installId);
}

}  // namespace

Result<DelegationCertificate> parseTrustedCertificate(ByteView certificateBytes) {
  std::optional<Json> json = parseJson(std::string_view(reinterpret_cast<const char*>(certificateBytes.data()),
                                                        certificateBytes.size()));
  if (!json.has_value()) {
    return Status::Malformed;
  }
  CertificateScalars scalars = readCertificateScalars(*json);
  Result<std::vector<std::string>> scopes = scopesFromJson(*json);
  bool wellFormed = scalars.complete() && scopes.ok() && *scalars.version == 1;
  if (!wellFormed || !hasValidCertificateIdentifiers(scalars) || scalars.installEncPub->size() != kPublicKeyBytes ||
      scalars.installSignPub->size() != kPublicKeyBytes) {
    return Status::Malformed;
  }
  DelegationCertificate certificate;
  certificate.certId = *scalars.certId;
  certificate.userId = *scalars.userId;
  certificate.installId = *scalars.installId;
  certificate.clientId = *scalars.clientId;
  certificate.installEncPub = std::move(*scalars.installEncPub);
  certificate.installSignPub = std::move(*scalars.installSignPub);
  certificate.scopes = scopes.take();
  certificate.issuedAt = *scalars.issuedAt;
  certificate.expiresAt = *scalars.expiresAt;
  certificate.originCertId = readString(*json, "originCertId");
  certificate.renewalCertId = readString(*json, "renewalCertId");
  bool linksConsistent = certificate.originCertId.has_value() == certificate.renewalCertId.has_value();
  bool linksValid = !certificate.originCertId.has_value() ||
                    (isLowercaseUuid(*certificate.originCertId) && isLowercaseUuid(*certificate.renewalCertId));
  if (!linksConsistent || !linksValid) {
    return Status::Malformed;
  }
  return certificate;
}

Result<DelegationCertificate> verifyCertificate(ByteView userSignPub, ByteView certificateBytes,
                                                ByteView certificateSignature,
                                                std::optional<int64_t> nowUnixSeconds) {
  if (!verifySignature(userSignPub, certificateSignatureMessage(certificateBytes), certificateSignature)) {
    return Status::AuthenticationFailed;
  }
  Result<DelegationCertificate> certificate = parseTrustedCertificate(certificateBytes);
  if (!certificate.ok()) {
    return certificate;
  }
  if (certificate.value().renewalCertId.has_value()) {
    return Status::AuthenticationFailed;
  }
  std::optional<int64_t> issuedAt = parseRfc3339Utc(certificate.value().issuedAt);
  std::optional<int64_t> expiresAt = parseRfc3339Utc(certificate.value().expiresAt);
  if (!issuedAt || !expiresAt) {
    return Status::Malformed;
  }
  if (!nowUnixSeconds.has_value()) {
    return certificate;
  }
  if (*nowUnixSeconds >= *expiresAt || *nowUnixSeconds < *issuedAt) {
    return Status::Expired;
  }
  return certificate;
}

namespace {

// Walks the keys until one verifies the signature. A failure other than a bad signature means
// the signature did verify and something else is wrong, which no other key can fix.
template <typename Verified, typename Verify, typename IssuedAt>
Result<Verified> verifyUnderKeys(const std::vector<IdentityVersion>& keys, Verify verify, IssuedAt issuedAt) {
  for (const IdentityVersion& key : keys) {
    Result<Verified> verified = verify(key.signPub);
    if (verified.status() == Status::AuthenticationFailed) {
      continue;
    }
    if (!verified.ok()) {
      return verified;
    }
    if (!keyValidAt(key, issuedAt(verified.value()))) {
      return Status::AuthenticationFailed;
    }
    return verified;
  }
  return Status::AuthenticationFailed;
}

}  // namespace

Result<DelegationCertificate> verifyCertificateUnderKeys(const std::vector<IdentityVersion>& keys,
                                                         ByteView certificateBytes, ByteView certificateSignature,
                                                         std::optional<int64_t> nowUnixSeconds) {
  return verifyUnderKeys<DelegationCertificate>(
      keys,
      [&](const Bytes& signPub) {
        return verifyCertificate(signPub, certificateBytes, certificateSignature, nowUnixSeconds);
      },
      [](const DelegationCertificate& certificate) { return certificate.issuedAt; });
}

Result<RenewalCertificate> verifyRenewalCertificateUnderKeys(const std::vector<IdentityVersion>& keys,
                                                             ByteView renewalBytes, ByteView renewalSignature,
                                                             std::optional<int64_t> nowUnixSeconds) {
  return verifyUnderKeys<RenewalCertificate>(
      keys,
      [&](const Bytes& signPub) {
        return verifyRenewalCertificate(signPub, renewalBytes, renewalSignature, nowUnixSeconds);
      },
      [](const RenewalCertificate& renewal) { return renewal.issuedAt; });
}

Result<RenewalCertificate> parseTrustedRenewalCertificate(ByteView renewalBytes) {
  std::optional<Json> json = parseJson(std::string_view(reinterpret_cast<const char*>(renewalBytes.data()),
                                                        renewalBytes.size()));
  if (!json.has_value()) {
    return Status::Malformed;
  }
  std::optional<uint64_t> version = readUnsigned(*json, "v");
  std::optional<std::string> renewalCertId = readString(*json, "renewalCertId");
  std::optional<std::string> userId = readString(*json, "userId");
  std::optional<std::string> deviceId = readString(*json, "deviceId");
  std::optional<Bytes> signPub = readBytes(*json, "renewalSignPub");
  std::optional<std::string> issuedAt = readString(*json, "issuedAt");
  std::optional<std::string> expiresAt = readString(*json, "expiresAt");
  bool complete = version && renewalCertId && userId && deviceId && signPub && issuedAt && expiresAt;
  if (!complete || *version != 1 || signPub->size() != kPublicKeyBytes || !isLowercaseUuid(*renewalCertId) ||
      !isLowercaseUuid(*userId) || !isLowercaseUuid(*deviceId)) {
    return Status::Malformed;
  }
  return RenewalCertificate{*renewalCertId, *userId, *deviceId, std::move(*signPub), *issuedAt, *expiresAt};
}

namespace {

Status checkValidity(const std::string& issuedAtText, const std::string& expiresAtText, std::optional<int64_t> now) {
  std::optional<int64_t> issuedAt = parseRfc3339Utc(issuedAtText);
  std::optional<int64_t> expiresAt = parseRfc3339Utc(expiresAtText);
  if (!issuedAt || !expiresAt) {
    return Status::Malformed;
  }
  if (now.has_value() && (*now >= *expiresAt || *now < *issuedAt)) {
    return Status::Expired;
  }
  return Status::Ok;
}

bool sameInstall(const DelegationCertificate& left, const DelegationCertificate& right) {
  return left.userId == right.userId && left.installId == right.installId && left.clientId == right.clientId &&
         left.installEncPub == right.installEncPub && left.installSignPub == right.installSignPub;
}

bool scopesWithin(const DelegationCertificate& renewed, const DelegationCertificate& origin) {
  return std::all_of(renewed.scopes.begin(), renewed.scopes.end(),
                     [&](const std::string& scope) { return certificateAllows(origin, scope); });
}

}  // namespace

Bytes encodeRenewalCertificate(const RenewalCertificate& renewal) {
  Json json = Json::object();
  json["v"] = 1;
  json["renewalCertId"] = renewal.renewalCertId;
  json["userId"] = renewal.userId;
  json["deviceId"] = renewal.deviceId;
  json["renewalSignPub"] = bytesToJson(renewal.renewalSignPub);
  json["issuedAt"] = renewal.issuedAt;
  json["expiresAt"] = renewal.expiresAt;
  return bytesOf(dumpCompact(json));
}

Bytes renewalSignatureMessage(ByteView renewalBytes) {
  return TlvWriter("nw-renewal-v1").bytes(renewalBytes).finish();
}

Result<Bytes> signRenewalCertificate(ByteView userSignSecret, ByteView renewalBytes) {
  return sign(userSignSecret, renewalSignatureMessage(renewalBytes));
}

Result<RenewalCertificate> verifyRenewalCertificate(ByteView userSignPub, ByteView renewalBytes,
                                                    ByteView renewalSignature, std::optional<int64_t> nowUnixSeconds) {
  if (!verifySignature(userSignPub, renewalSignatureMessage(renewalBytes), renewalSignature)) {
    return Status::AuthenticationFailed;
  }
  Result<RenewalCertificate> renewal = parseTrustedRenewalCertificate(renewalBytes);
  if (!renewal.ok()) {
    return renewal;
  }
  Status validity = checkValidity(renewal.value().issuedAt, renewal.value().expiresAt, nowUnixSeconds);
  if (validity != Status::Ok) {
    return validity;
  }
  return renewal;
}

Result<DelegationCertificate> verifyRenewedCertificate(const RenewalCertificate& renewal,
                                                       const DelegationCertificate& origin, ByteView certificateBytes,
                                                       ByteView certificateSignature,
                                                       std::optional<int64_t> nowUnixSeconds) {
  if (!verifySignature(renewal.renewalSignPub, certificateSignatureMessage(certificateBytes), certificateSignature)) {
    return Status::AuthenticationFailed;
  }
  Result<DelegationCertificate> parsed = parseTrustedCertificate(certificateBytes);
  if (!parsed.ok()) {
    return parsed;
  }
  const DelegationCertificate& renewed = parsed.value();
  bool linked = renewed.renewalCertId == renewal.renewalCertId && renewed.originCertId == origin.certId &&
                !origin.renewalCertId.has_value() && renewed.userId == renewal.userId;
  if (!linked || !sameInstall(renewed, origin) || !scopesWithin(renewed, origin)) {
    return Status::AuthenticationFailed;
  }
  Status validity = checkValidity(renewed.issuedAt, renewed.expiresAt, nowUnixSeconds);
  if (validity != Status::Ok) {
    return validity;
  }
  std::optional<int64_t> renewedExpiry = parseRfc3339Utc(renewed.expiresAt);
  std::optional<int64_t> renewalExpiry = parseRfc3339Utc(renewal.expiresAt);
  if (*renewedExpiry > *renewalExpiry) {
    return Status::AuthenticationFailed;
  }
  return parsed;
}

bool certificateAllows(const DelegationCertificate& certificate, std::string_view scope) {
  return std::find(certificate.scopes.begin(), certificate.scopes.end(), scope) != certificate.scopes.end();
}

Status verifyInstallAuthoredNode(const DelegationCertificate& certificate, const Node& node) {
  bool bindsToInstall = node.authorType == "install" && node.authorId == certificate.installId &&
                        node.certId.has_value() && *node.certId == certificate.certId;
  if (!bindsToInstall) {
    return Status::AuthenticationFailed;
  }
  if (!certificateAllows(certificate, node.collection + ":write")) {
    return Status::Forbidden;
  }
  if (!verifyNodeWrite(certificate.installSignPub, node)) {
    return Status::AuthenticationFailed;
  }
  return Status::Ok;
}

}  // namespace nw
