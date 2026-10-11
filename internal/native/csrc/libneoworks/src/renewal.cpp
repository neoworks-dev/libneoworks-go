#include "renewal.hpp"

#include <algorithm>

#include "timeutil.hpp"

namespace nw {

Result<RenewedCertificate> renewDelegationCertificate(ByteView renewalSecret, const std::string& renewalCertId,
                                                      ByteView currentCertificateBytes, int64_t nowUnixSeconds,
                                                      int64_t lifetimeSeconds, int64_t renewalExpiresUnixSeconds) {
  if (renewalExpiresUnixSeconds <= nowUnixSeconds || lifetimeSeconds <= 0) {
    return Status::Expired;
  }
  Result<DelegationCertificate> parsed = parseTrustedCertificate(currentCertificateBytes);
  if (!parsed.ok()) {
    return parsed.status();
  }
  DelegationCertificate renewed = parsed.take();
  std::string originCertId = renewed.certId;
  if (renewed.originCertId.has_value()) {
    originCertId = *renewed.originCertId;
  }
  renewed.certId = newUuid();
  renewed.originCertId = originCertId;
  renewed.renewalCertId = renewalCertId;
  renewed.issuedAt = formatRfc3339Utc(nowUnixSeconds);
  renewed.expiresAt = formatRfc3339Utc(std::min(nowUnixSeconds + lifetimeSeconds, renewalExpiresUnixSeconds));

  RenewedCertificate result;
  result.certificateBytes = encodeCertificate(renewed);
  Result<Bytes> signature = signCertificate(renewalSecret, result.certificateBytes);
  if (!signature.ok()) {
    return signature.status();
  }
  result.signature = signature.take();
  result.certificate = std::move(renewed);
  return result;
}

}  // namespace nw
