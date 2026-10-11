#include "keystore.hpp"

#include <sodium.h>

#include "tlv.hpp"

namespace nw {

namespace {

void wipe(Bytes& bytes) {
  if (!bytes.empty()) {
    sodium_memzero(bytes.data(), bytes.size());
  }
}

class CallbackKeystore : public Keystore {
 public:
  explicit CallbackKeystore(KeystoreCallbacks callbacks) : callbacks_(std::move(callbacks)) {}

  std::string backendName() const override { return callbacks_.backendName; }

  Status probe() override { return Status::Ok; }

  Result<Bytes> wrapSecret(ByteView secret, ByteView label) override { return callbacks_.wrap(secret, label); }

  Result<SecretBytes> unwrapSecret(ByteView wrapped, ByteView label) override {
    Result<Bytes> plaintext = callbacks_.unwrap(wrapped, label);
    if (!plaintext.ok()) {
      return plaintext.status();
    }
    SecretBytes secret{ByteView(plaintext.value())};
    wipe(plaintext.value());
    return secret;
  }

 private:
  KeystoreCallbacks callbacks_;
};

class EphemeralProvider : public MasterKeyProvider {
 public:
  EphemeralProvider() : key_(SymmetricKey::random()) {}
  std::string backendName() const override { return "ephemeral"; }
  Result<SymmetricKey> loadOrCreateMasterKey() override { return SymmetricKey::fromBytes(key_.view()); }

 private:
  SymmetricKey key_;
};

Bytes keystoreAad(const std::string& backendName, ByteView label) {
  return TlvWriter("nw-keystore-v1").text(backendName).bytes(label).finish();
}

class MasterKeyKeystore : public Keystore {
 public:
  explicit MasterKeyKeystore(std::unique_ptr<MasterKeyProvider> provider) : provider_(std::move(provider)) {}

  std::string backendName() const override { return provider_->backendName(); }

  Status probe() override { return provider_->loadOrCreateMasterKey().status(); }

  Result<Bytes> wrapSecret(ByteView secret, ByteView label) override {
    Result<SymmetricKey> masterKey = provider_->loadOrCreateMasterKey();
    if (!masterKey.ok()) {
      return masterKey.status();
    }
    return aeadEncrypt(masterKey.value(), secret, keystoreAad(provider_->backendName(), label));
  }

  Result<SecretBytes> unwrapSecret(ByteView wrapped, ByteView label) override {
    Result<SymmetricKey> masterKey = provider_->loadOrCreateMasterKey();
    if (!masterKey.ok()) {
      return masterKey.status();
    }
    return aeadDecryptSecret(masterKey.value(), wrapped, keystoreAad(provider_->backendName(), label));
  }

 private:
  std::unique_ptr<MasterKeyProvider> provider_;
};

class FirstAvailableKeystore : public Keystore {
 public:
  explicit FirstAvailableKeystore(std::vector<std::unique_ptr<Keystore>> candidates)
      : candidates_(std::move(candidates)) {}

  std::string backendName() const override {
    if (selected_ == nullptr) {
      return "none";
    }
    return selected_->backendName();
  }

  Status probe() override {
    if (selected_ != nullptr) {
      return Status::Ok;
    }
    for (std::unique_ptr<Keystore>& candidate : candidates_) {
      if (candidate->probe() == Status::Ok) {
        selected_ = candidate.get();
        return Status::Ok;
      }
    }
    return Status::Unsupported;
  }

  Result<Bytes> wrapSecret(ByteView secret, ByteView label) override {
    if (probe() != Status::Ok) {
      return Status::Unsupported;
    }
    return selected_->wrapSecret(secret, label);
  }

  Result<SecretBytes> unwrapSecret(ByteView wrapped, ByteView label) override {
    if (probe() != Status::Ok) {
      return Status::Unsupported;
    }
    return selected_->unwrapSecret(wrapped, label);
  }

 private:
  std::vector<std::unique_ptr<Keystore>> candidates_;
  Keystore* selected_ = nullptr;
};

}  // namespace

std::unique_ptr<Keystore> makeCallbackKeystore(KeystoreCallbacks callbacks) {
  return std::make_unique<CallbackKeystore>(std::move(callbacks));
}

std::unique_ptr<Keystore> makeEphemeralKeystore() {
  return std::make_unique<MasterKeyKeystore>(std::make_unique<EphemeralProvider>());
}

std::unique_ptr<Keystore> makeMasterKeyKeystore(std::unique_ptr<MasterKeyProvider> provider) {
  return std::make_unique<MasterKeyKeystore>(std::move(provider));
}

std::unique_ptr<Keystore> makeFirstAvailableKeystore(std::vector<std::unique_ptr<Keystore>> candidates) {
  return std::make_unique<FirstAvailableKeystore>(std::move(candidates));
}

std::unique_ptr<Keystore> makeLinuxKeystore(const std::string& applicationId, const std::string& dataDirectory) {
  std::vector<std::unique_ptr<Keystore>> chain;
#if defined(NW_HAVE_TPM2)
  chain.push_back(makeMasterKeyKeystore(makeTpm2Provider("", dataDirectory + "/tpm2-master.blob")));
#endif
#if defined(NW_HAVE_LIBSECRET)
  chain.push_back(makeMasterKeyKeystore(makeLibsecretProvider(applicationId)));
#endif
  (void)applicationId;
  (void)dataDirectory;
  return makeFirstAvailableKeystore(std::move(chain));
}

}  // namespace nw
