#include <libsecret/secret.h>
#include <sodium.h>

#include <string>

#include "keystore.hpp"

namespace nw {

namespace {

const SecretSchema* masterKeySchema() {
  static SecretSchema schema = {};
  schema.name = "dev.neoworks.libneoworks.master-key";
  schema.flags = SECRET_SCHEMA_NONE;
  schema.attributes[0].name = "application";
  schema.attributes[0].type = SECRET_SCHEMA_ATTRIBUTE_STRING;
  return &schema;
}

class LibsecretProvider : public MasterKeyProvider {
 public:
  explicit LibsecretProvider(std::string applicationId) : applicationId_(std::move(applicationId)) {}

  std::string backendName() const override { return "libsecret"; }

  Result<SymmetricKey> loadOrCreateMasterKey() override {
    Result<SymmetricKey> existing = lookup();
    if (existing.ok() || existing.status() != Status::NotFound) {
      return existing;
    }
    SymmetricKey created = SymmetricKey::random();
    std::string encoded = toBase64Url(created.view());
    GError* error = nullptr;
    gboolean stored = secret_password_store_sync(masterKeySchema(), SECRET_COLLECTION_DEFAULT,
                                                 "Neoworks install master key", encoded.c_str(), nullptr,
                                                 &error, "application", applicationId_.c_str(), nullptr);
    sodium_memzero(encoded.data(), encoded.size());
    if (!stored) {
      g_clear_error(&error);
      return Status::IoFailure;
    }
    return created;
  }

 private:
  Result<SymmetricKey> lookup() {
    GError* error = nullptr;
    gchar* password = secret_password_lookup_sync(masterKeySchema(), nullptr, &error, "application",
                                                  applicationId_.c_str(), nullptr);
    if (error != nullptr) {
      g_clear_error(&error);
      return Status::IoFailure;
    }
    if (password == nullptr) {
      return Status::NotFound;
    }
    std::optional<Bytes> decoded = fromBase64Url(password);
    secret_password_free(password);
    if (!decoded.has_value()) {
      return Status::Malformed;
    }
    Result<SymmetricKey> key = SymmetricKey::fromBytes(*decoded);
    sodium_memzero(decoded->data(), decoded->size());
    return key;
  }

  std::string applicationId_;
};

}  // namespace

std::unique_ptr<MasterKeyProvider> makeLibsecretProvider(const std::string& applicationId) {
  return std::make_unique<LibsecretProvider>(applicationId);
}

}  // namespace nw
