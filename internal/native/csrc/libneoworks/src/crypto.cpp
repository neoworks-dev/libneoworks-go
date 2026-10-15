#include "crypto.hpp"

#include <sodium.h>

namespace nw {

Status initializeCrypto() {
  if (sodium_init() < 0) {
    return Status::CryptoFailure;
  }
  return Status::Ok;
}

Result<SymmetricKey> SymmetricKey::fromBytes(ByteView source) {
  if (source.size() != kKeyBytes) {
    return Status::Malformed;
  }
  return SymmetricKey(SecretBytes(source));
}

SymmetricKey SymmetricKey::random() { return SymmetricKey(randomSecret(kKeyBytes)); }

SymmetricKey SymmetricKey::zeroed() { return SymmetricKey(SecretBytes(kKeyBytes)); }

void fillRandom(uint8_t* destination, size_t length) { randombytes_buf(destination, length); }

Bytes randomBytes(size_t length) {
  Bytes bytes(length);
  fillRandom(bytes.data(), length);
  return bytes;
}

SecretBytes randomSecret(size_t length) {
  SecretBytes secret(length);
  fillRandom(secret.data(), length);
  return secret;
}

std::string newUuid() {
  Bytes raw = randomBytes(16);
  raw[6] = static_cast<uint8_t>((raw[6] & 0x0f) | 0x40);
  raw[8] = static_cast<uint8_t>((raw[8] & 0x3f) | 0x80);
  std::string hexText = toHex(raw);
  return hexText.substr(0, 8) + "-" + hexText.substr(8, 4) + "-" + hexText.substr(12, 4) + "-" +
         hexText.substr(16, 4) + "-" + hexText.substr(20, 12);
}

Bytes aeadEncrypt(const SymmetricKey& key, ByteView message, ByteView associatedData) {
  Bytes boxed(kNonceBytes + message.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
  fillRandom(boxed.data(), kNonceBytes);
  unsigned long long ciphertextLength = 0;
  crypto_aead_xchacha20poly1305_ietf_encrypt(boxed.data() + kNonceBytes, &ciphertextLength, message.data(),
                                             message.size(), associatedData.data(), associatedData.size(),
                                             nullptr, boxed.data(), key.data());
  boxed.resize(kNonceBytes + ciphertextLength);
  return boxed;
}

namespace {

bool hasAeadShape(ByteView boxed) {
  return boxed.size() >= kNonceBytes + crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

int decryptInto(uint8_t* plaintext, unsigned long long* plaintextLength, const SymmetricKey& key, ByteView boxed,
                ByteView associatedData) {
  return crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext, plaintextLength, nullptr, boxed.data() + kNonceBytes, boxed.size() - kNonceBytes,
      associatedData.data(), associatedData.size(), boxed.data(), key.data());
}

}  // namespace

Result<Bytes> aeadDecrypt(const SymmetricKey& key, ByteView boxed, ByteView associatedData) {
  if (!hasAeadShape(boxed)) {
    return Status::Malformed;
  }
  Bytes plaintext(boxed.size() - kNonceBytes - crypto_aead_xchacha20poly1305_ietf_ABYTES);
  unsigned long long plaintextLength = 0;
  if (decryptInto(plaintext.data(), &plaintextLength, key, boxed, associatedData) != 0) {
    return Status::AuthenticationFailed;
  }
  plaintext.resize(plaintextLength);
  return plaintext;
}

Result<SecretBytes> aeadDecryptSecret(const SymmetricKey& key, ByteView boxed, ByteView associatedData) {
  if (!hasAeadShape(boxed)) {
    return Status::Malformed;
  }
  SecretBytes plaintext(boxed.size() - kNonceBytes - crypto_aead_xchacha20poly1305_ietf_ABYTES);
  unsigned long long plaintextLength = 0;
  if (decryptInto(plaintext.data(), &plaintextLength, key, boxed, associatedData) != 0) {
    return Status::AuthenticationFailed;
  }
  return plaintext;
}

Result<SymmetricKey> aeadDecryptKey(const SymmetricKey& key, ByteView boxed, ByteView associatedData) {
  Result<SecretBytes> plaintext = aeadDecryptSecret(key, boxed, associatedData);
  if (!plaintext.ok()) {
    return plaintext.status();
  }
  return SymmetricKey::fromBytes(plaintext.value().view());
}

Result<Bytes> seal(ByteView recipientPublicKey, ByteView message) {
  if (recipientPublicKey.size() != crypto_box_PUBLICKEYBYTES) {
    return Status::Malformed;
  }
  Bytes sealed(crypto_box_SEALBYTES + message.size());
  crypto_box_seal(sealed.data(), message.data(), message.size(), recipientPublicKey.data());
  return sealed;
}

Result<SecretBytes> sealOpen(ByteView publicKey, ByteView secretKey, ByteView sealed) {
  bool wellFormed = publicKey.size() == crypto_box_PUBLICKEYBYTES &&
                    secretKey.size() == crypto_box_SECRETKEYBYTES && sealed.size() >= crypto_box_SEALBYTES;
  if (!wellFormed) {
    return Status::Malformed;
  }
  SecretBytes message(sealed.size() - crypto_box_SEALBYTES);
  int status = crypto_box_seal_open(message.data(), sealed.data(), sealed.size(), publicKey.data(),
                                    secretKey.data());
  if (status != 0) {
    return Status::AuthenticationFailed;
  }
  return message;
}

SymmetricKey kdf(const SymmetricKey& key, uint64_t subkeyId, std::string_view context) {
  if (context.size() != crypto_kdf_CONTEXTBYTES) {
    sodium_misuse();
  }
  SymmetricKey subkey = SymmetricKey::zeroed();
  const std::string contextText(context);
  crypto_kdf_derive_from_key(subkey.mutableData(), kKeyBytes, subkeyId, contextText.c_str(), key.data());
  return subkey;
}

SymmetricKey keyedHash(const SymmetricKey& key, ByteView input) {
  SymmetricKey derived = SymmetricKey::zeroed();
  crypto_generichash(derived.mutableData(), kKeyBytes, input.data(), input.size(), key.data(), kKeyBytes);
  return derived;
}

Bytes hash(ByteView message) {
  Bytes digest(crypto_generichash_BYTES);
  crypto_generichash(digest.data(), digest.size(), message.data(), message.size(), nullptr, 0);
  return digest;
}

SignKeypair generateSignKeypair() {
  SecretBytes seed = randomSecret(crypto_sign_SEEDBYTES);
  SignKeypair keypair{Bytes(crypto_sign_PUBLICKEYBYTES), SecretBytes(crypto_sign_SECRETKEYBYTES)};
  crypto_sign_seed_keypair(keypair.publicKey.data(), keypair.secretKey.data(), seed.data());
  return keypair;
}

BoxKeypair generateBoxKeypair() {
  SecretBytes seed = randomSecret(crypto_box_SEEDBYTES);
  BoxKeypair keypair{Bytes(crypto_box_PUBLICKEYBYTES), SecretBytes(crypto_box_SECRETKEYBYTES)};
  crypto_box_seed_keypair(keypair.publicKey.data(), keypair.secretKey.data(), seed.data());
  return keypair;
}

Result<Bytes> sign(ByteView secretKey, ByteView message) {
  if (secretKey.size() != crypto_sign_SECRETKEYBYTES) {
    return Status::Malformed;
  }
  Bytes signature(crypto_sign_BYTES);
  crypto_sign_detached(signature.data(), nullptr, message.data(), message.size(), secretKey.data());
  return signature;
}

bool verifySignature(ByteView publicKey, ByteView message, ByteView signature) {
  if (publicKey.size() != crypto_sign_PUBLICKEYBYTES || signature.size() != crypto_sign_BYTES) {
    return false;
  }
  return crypto_sign_verify_detached(signature.data(), message.data(), message.size(), publicKey.data()) == 0;
}

Result<SymmetricKey> passwordHash(ByteView password, const PwhashParameters& parameters) {
  if (parameters.salt.size() != crypto_pwhash_SALTBYTES) {
    return Status::InvalidArgument;
  }
  SymmetricKey derived = SymmetricKey::zeroed();
  int status = crypto_pwhash(derived.mutableData(), kKeyBytes, reinterpret_cast<const char*>(password.data()),
                             password.size(), parameters.salt.data(), parameters.opsLimit,
                             parameters.memLimit, crypto_pwhash_ALG_ARGON2ID13);
  if (status != 0) {
    return Status::CryptoFailure;
  }
  return derived;
}

Bytes pad(ByteView message) {
  Bytes padded(message.begin(), message.end());
  padded.resize(message.size() + kPadBlockBytes);
  size_t paddedLength = 0;
  sodium_pad(&paddedLength, padded.data(), message.size(), kPadBlockBytes, padded.size());
  padded.resize(paddedLength);
  return padded;
}

Result<Bytes> unpad(ByteView padded) {
  if (padded.empty()) {
    return Status::Malformed;
  }
  Bytes buffer(padded.begin(), padded.end());
  size_t unpaddedLength = 0;
  if (sodium_unpad(&unpaddedLength, buffer.data(), buffer.size(), kPadBlockBytes) != 0) {
    return Status::Malformed;
  }
  buffer.resize(unpaddedLength);
  return buffer;
}

}  // namespace nw
