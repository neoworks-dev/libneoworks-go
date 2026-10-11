#pragma once

#include <string>

#include "delegation.hpp"

namespace nw {

// A delegation certificate extended by an authenticator's renewal key (amendment 3).
struct RenewedCertificate {
  DelegationCertificate certificate;
  Bytes certificateBytes;
  Bytes signature;
};

// Extends `currentCertificateBytes` (the install's newest certificate, identity-signed or already
// renewed) for `lifetimeSeconds`, capped at the renewal certificate's own expiry. Install keys,
// client and scopes carry over; originCertId names the identity-signed certificate at the root of
// the chain. Expired: the renewal certificate is past its expiry.
Result<RenewedCertificate> renewDelegationCertificate(ByteView renewalSecret, const std::string& renewalCertId,
                                                      ByteView currentCertificateBytes, int64_t nowUnixSeconds,
                                                      int64_t lifetimeSeconds, int64_t renewalExpiresUnixSeconds);

}  // namespace nw
