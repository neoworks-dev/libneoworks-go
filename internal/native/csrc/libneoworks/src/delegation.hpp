#pragma once

#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "identity_history.hpp"
#include "json.hpp"
#include "node.hpp"

namespace nw {

struct DelegationCertificate {
  std::string certId;
  std::string userId;
  std::string installId;
  std::string clientId;
  Bytes installEncPub;
  Bytes installSignPub;
  std::vector<std::string> scopes;
  std::string issuedAt;
  std::string expiresAt;
  // Set on a certificate an authenticator's renewal key extended: the
  // identity-signed certificate it extends and the renewal certificate that signed it.
  std::optional<std::string> originCertId;
  std::optional<std::string> renewalCertId;
};

// Lets one authenticator device extend delegation certificates (amendment 3). The user's
// identity key signs it once at enrollment; it is valid for a year.
struct RenewalCertificate {
  std::string renewalCertId;
  std::string userId;
  std::string deviceId;
  Bytes renewalSignPub;
  std::string issuedAt;
  std::string expiresAt;
};

// certBytes: compact UTF-8 JSON {v:1, certId, userId, installId, clientId,
// installEncPub, installSignPub, scopes, issuedAt, expiresAt}, binary as base64url.
Bytes encodeCertificate(const DelegationCertificate& certificate);
Bytes certificateSignatureMessage(ByteView certificateBytes);
Result<Bytes> signCertificate(ByteView userSignSecret, ByteView certificateBytes);

// Parses without checking any signature. Only for bytes verified earlier, such
// as records read back from the authenticated local store.
Result<DelegationCertificate> parseTrustedCertificate(ByteView certificateBytes);

// Verifies the signature before parsing; the bytes are never parsed otherwise.
// With a time, the certificate must be inside its validity window; without one
// only the signature and structure are checked (historic nodes stay verifiable).
Result<DelegationCertificate> verifyCertificate(ByteView userSignPub, ByteView certificateBytes,
                                                ByteView certificateSignature,
                                                std::optional<int64_t> nowUnixSeconds);

// Like verifyCertificate, under whichever key of the user's identity history signed it. A key
// that was already retired when the certificate claims to be issued does not count.
Result<DelegationCertificate> verifyCertificateUnderKeys(const std::vector<IdentityVersion>& keys,
                                                         ByteView certificateBytes, ByteView certificateSignature,
                                                         std::optional<int64_t> nowUnixSeconds);

// Parses without checking any signature; only for bytes verified earlier.
Result<RenewalCertificate> parseTrustedRenewalCertificate(ByteView renewalBytes);

Bytes encodeRenewalCertificate(const RenewalCertificate& renewal);
Bytes renewalSignatureMessage(ByteView renewalBytes);
Result<Bytes> signRenewalCertificate(ByteView userSignSecret, ByteView renewalBytes);

// Verifies the user's signature before parsing. With a time, the certificate must be valid then.
Result<RenewalCertificate> verifyRenewalCertificate(ByteView userSignPub, ByteView renewalBytes,
                                                    ByteView renewalSignature, std::optional<int64_t> nowUnixSeconds);

Result<RenewalCertificate> verifyRenewalCertificateUnderKeys(const std::vector<IdentityVersion>& keys,
                                                             ByteView renewalBytes, ByteView renewalSignature,
                                                             std::optional<int64_t> nowUnixSeconds);

// Verifies a certificate signed by a renewal key against its renewal certificate and its
// identity-signed origin: same user, install, client and install keys, scopes a subset of the
// origin's, and not outliving the renewal certificate. The origin's own expiry is not checked,
// because renewals outlive it.
Result<DelegationCertificate> verifyRenewedCertificate(const RenewalCertificate& renewal,
                                                       const DelegationCertificate& origin, ByteView certificateBytes,
                                                       ByteView certificateSignature,
                                                       std::optional<int64_t> nowUnixSeconds);

bool certificateAllows(const DelegationCertificate& certificate, std::string_view scope);

// Install-authored node: signature checked against the certificate's install key
// and the certificate must carry `<collection>:write`.
Status verifyInstallAuthoredNode(const DelegationCertificate& certificate, const Node& node);

}  // namespace nw
