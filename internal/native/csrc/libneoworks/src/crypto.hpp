#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "bytes.hpp"
#include "status.hpp"

namespace nw {

constexpr size_t kKeyBytes = 32;
constexpr size_t kNonceBytes = 24;
constexpr size_t kPadBlockBytes = 256;
constexpr size_t kSignatureBytes = 64;
constexpr size_t kPublicKeyBytes = 32;
constexpr size_t kEncSecretBytes = 32;
constexpr size_t kSignSecretBytes = 64;
constexpr size_t kPwhashSaltBytes = 16;
constexpr unsigned long long kPwhashOpsLimit = 3;
constexpr size_t kPwhashMemLimit = 67108864;

// A 32-byte secret key. The size invariant is enforced at construction, so
// primitives taking a SymmetricKey cannot be handed a short buffer.
class SymmetricKey {
 public:
  SymmetricKey() = default;
  static Result<SymmetricKey> fromBytes(ByteView source);
  static SymmetricKey random();
  static SymmetricKey zeroed();

  ByteView view() const { return secret_.view(); }
  const uint8_t* data() const { return secret_.data(); }
  uint8_t* mutableData() { return secret_.data(); }
  bool valid() const { return secret_.size() == kKeyBytes; }
  SymmetricKey clone() const { return SymmetricKey(SecretBytes(secret_.view())); }

 private:
  explicit SymmetricKey(SecretBytes secret) : secret_(std::move(secret)) {}

  SecretBytes secret_;
};

Status initializeCrypto();
void fillRandom(uint8_t* destination, size_t length);
Bytes randomBytes(size_t length);
SecretBytes randomSecret(size_t length);
// Lowercase UUIDv4 from the random source.
std::string newUuid();

// aead(key, msg, aad) = nonce(24) || ciphertext+tag, XChaCha20-Poly1305-IETF.
Bytes aeadEncrypt(const SymmetricKey& key, ByteView message, ByteView associatedData);
Result<Bytes> aeadDecrypt(const SymmetricKey& key, ByteView boxed, ByteView associatedData);
Result<SymmetricKey> aeadDecryptKey(const SymmetricKey& key, ByteView boxed, ByteView associatedData);
Result<SecretBytes> aeadDecryptSecret(const SymmetricKey& key, ByteView boxed, ByteView associatedData);

Result<Bytes> seal(ByteView recipientPublicKey, ByteView message);
Result<SecretBytes> sealOpen(ByteView publicKey, ByteView secretKey, ByteView sealed);

// 32-byte subkey; context must be exactly 8 characters.
SymmetricKey kdf(const SymmetricKey& key, uint64_t subkeyId, std::string_view context);

// BLAKE2b-256 of `input` keyed with `key`.
SymmetricKey keyedHash(const SymmetricKey& key, ByteView input);

Bytes hash(ByteView message);

struct SignKeypair {
  Bytes publicKey;
  SecretBytes secretKey;
};
struct BoxKeypair {
  Bytes publicKey;
  SecretBytes secretKey;
};
SignKeypair generateSignKeypair();
BoxKeypair generateBoxKeypair();

Result<Bytes> sign(ByteView secretKey, ByteView message);
bool verifySignature(ByteView publicKey, ByteView message, ByteView signature);

struct PwhashParameters {
  Bytes salt;
  unsigned long long opsLimit = kPwhashOpsLimit;
  size_t memLimit = kPwhashMemLimit;
};
Result<SymmetricKey> passwordHash(ByteView password, const PwhashParameters& parameters);

Bytes pad(ByteView message);
Result<Bytes> unpad(ByteView padded);

}  // namespace nw
