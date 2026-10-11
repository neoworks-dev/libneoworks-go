#pragma once

#include <optional>
#include <string>
#include <vector>

#include "account.hpp"
#include "crypto.hpp"
#include "json.hpp"

namespace nw {

// One version of a user's identity key pair (contract amendment 4). Version 1 has no
// rotationSig; every later version carries the previous version's signature over its keys.
struct IdentityVersion {
  uint32_t version = 0;
  Bytes signPub;
  Bytes encPub;
  Bytes rotationSig;
  std::string createdAt;
  // Set once the next version exists.
  std::optional<std::string> retiredAt;
};

// rotationSig = sign(previousSignSec, tlv("nw-identity-rotation-v1", userId, u32 version, signPub, encPub)).
Bytes identityRotationMessage(std::string_view userId, uint32_t version, ByteView signPub, ByteView encPub);
Result<Bytes> signIdentityRotation(ByteView previousSignSecret, std::string_view userId, uint32_t version,
                                   ByteView signPub, ByteView encPub);

// Versions must be contiguous from 1 and every rotationSig must verify under the version before.
Status verifyIdentityHistory(const std::string& userId, const std::vector<IdentityVersion>& versions);

// The history must verify and end in the identity the server serves now.
Status verifyHistoryEndsAt(const PublicIdentity& identity, const std::vector<IdentityVersion>& history);

Json identityVersionToJson(const IdentityVersion& version);
Result<IdentityVersion> identityVersionFromJson(const Json& json);
// Reads the `keys` array of GET /users/{id}/identity-keys, or a bare array.
Result<std::vector<IdentityVersion>> identityHistoryFromJson(const Json& json);
Json identityHistoryToJson(const std::vector<IdentityVersion>& versions);

// A key that signed something at `issuedAt` is acceptable unless its version was already
// retired by then. Unparseable times are refused.
bool keyValidAt(const IdentityVersion& version, const std::string& issuedAt);

}  // namespace nw
