#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "crypto.hpp"

namespace nw {

// Wraps small secrets under a key that never leaves the operating system's key
// storage. The wrapped blob is opaque to the caller and safe to persist.
class Keystore {
 public:
  virtual ~Keystore() = default;
  virtual std::string backendName() const = 0;
  // Ok when the backend can protect secrets on this machine right now.
  virtual Status probe() = 0;
  virtual Result<Bytes> wrapSecret(ByteView secret, ByteView label) = 0;
  virtual Result<SecretBytes> unwrapSecret(ByteView wrapped, ByteView label) = 0;
};

// Host-implemented keystore: Android Keystore through JNI, a non-extractable
// WebCrypto key in the browser, Keychain on Apple platforms.
struct KeystoreCallbacks {
  std::string backendName;
  std::function<Result<Bytes>(ByteView secret, ByteView label)> wrap;
  std::function<Result<Bytes>(ByteView wrapped, ByteView label)> unwrap;
};
std::unique_ptr<Keystore> makeCallbackKeystore(KeystoreCallbacks callbacks);

// Process-lifetime key in locked memory. For tests and short-lived tools only:
// nothing survives the process.
std::unique_ptr<Keystore> makeEphemeralKeystore();

// A random 32-byte master key held by `provider`; secrets are wrapped with aead
// under that key. Used by backends that can only store a secret, not wrap data
// (libsecret, TPM2 sealed objects).
class MasterKeyProvider {
 public:
  virtual ~MasterKeyProvider() = default;
  virtual std::string backendName() const = 0;
  // Creates and stores the key on first use.
  virtual Result<SymmetricKey> loadOrCreateMasterKey() = 0;
};
std::unique_ptr<Keystore> makeMasterKeyKeystore(std::unique_ptr<MasterKeyProvider> provider);

// First backend that reports itself usable wins. No backend means an error,
// never a silent fallback to unprotected storage.
std::unique_ptr<Keystore> makeFirstAvailableKeystore(std::vector<std::unique_ptr<Keystore>> candidates);

#if defined(NW_HAVE_LIBSECRET)
std::unique_ptr<MasterKeyProvider> makeLibsecretProvider(const std::string& applicationId);
#endif
#if defined(NW_HAVE_TPM2)
std::unique_ptr<MasterKeyProvider> makeTpm2Provider(const std::string& tctiConfiguration, const std::string& blobPath);
#endif

// Linux default chain: TPM2, then libsecret.
std::unique_ptr<Keystore> makeLinuxKeystore(const std::string& applicationId, const std::string& dataDirectory);

}  // namespace nw
