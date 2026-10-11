#include "capi_internal.hpp"
#include "descriptor.hpp"
#include "identity_history.hpp"
#include "contact_code.hpp"
#include "recovery_words.hpp"
#include "renewal.hpp"

#if defined(NW_ENABLE_TEST_HOOKS)
#include "testing.hpp"
#endif

namespace nw::capi {

void clearBuffer(nw_buffer* buffer) {
  buffer->data = nullptr;
  buffer->length = 0;
  buffer->secret = 0;
}

int fillBuffer(nw_buffer* out, ByteView data, bool secret) {
  clearBuffer(out);
  if (data.empty()) {
    return kOk;
  }
  if (secret) {
    out->data = static_cast<uint8_t*>(sodium_malloc(data.size()));
  } else {
    out->data = static_cast<uint8_t*>(std::malloc(data.size()));
  }
  if (out->data == nullptr) {
    return NW_ERR_INTERNAL;
  }
  std::memcpy(out->data, data.data(), data.size());
  out->length = data.size();
  out->secret = secret;
  return kOk;
}

int fillText(nw_buffer* out, const std::string& text) { return fillBuffer(out, viewOf(text), false); }

int fillJson(nw_buffer* out, const Json& json) { return fillText(out, dumpCompact(json)); }

std::optional<Json> parseText(const char* text) {
  if (text == nullptr) {
    return std::nullopt;
  }
  return parseJson(text);
}

ByteView viewOfInput(const uint8_t* data, size_t length) {
  if (data == nullptr) {
    return ByteView();
  }
  return ByteView(data, length);
}

std::string textOrEmpty(const char* text) {
  if (text == nullptr) {
    return std::string();
  }
  return text;
}

namespace {

Result<PwhashParameters> parsePwhashParameters(const char* paramsJson) {
  std::optional<Json> json = parseText(paramsJson);
  if (!json.has_value()) {
    return Status::Malformed;
  }
  std::optional<Bytes> salt = readBytes(*json, "salt");
  std::optional<uint64_t> opsLimit = readUnsigned(*json, "opsLimit");
  std::optional<uint64_t> memLimit = readUnsigned(*json, "memLimit");
  if (!salt || !opsLimit || !memLimit) {
    return Status::Malformed;
  }
  PwhashParameters parameters;
  parameters.salt = std::move(*salt);
  parameters.opsLimit = *opsLimit;
  parameters.memLimit = static_cast<size_t>(*memLimit);
  return parameters;
}

Result<PwhashParameters> bundleOrExplicitParameters(const KeyBundle& bundle, const char* paramsJson) {
  if (paramsJson != nullptr) {
    return parsePwhashParameters(paramsJson);
  }
  if (!bundle.pwhash.has_value()) {
    return Status::Malformed;
  }
  PwhashParameters parameters;
  parameters.salt = bundle.pwhash->salt;
  parameters.opsLimit = bundle.pwhash->opsLimit;
  parameters.memLimit = static_cast<size_t>(bundle.pwhash->memLimit);
  return parameters;
}

Result<KeyBundle> parseBundle(const char* bundleJson) {
  std::optional<Json> json = parseText(bundleJson);
  if (!json.has_value()) {
    return Status::Malformed;
  }
  return keyBundleFromJson(*json);
}

int publishAccount(Result<Account> account, nw_account** out) {
  if (!account.ok()) {
    return code(account.status());
  }
  *out = new nw_account{account.take()};
  return kOk;
}

Json installDescription(const Install& install) {
  Json json = Json::object();
  json["installId"] = install.installId;
  json["installEncPub"] = toBase64Url(install.encPub);
  json["installSignPub"] = toBase64Url(install.signPub);
  return json;
}

}  // namespace

}  // namespace nw::capi

using namespace nw;
using namespace nw::capi;

extern "C" {

int nw_init(void) { return guarded([] { return code(initializeCrypto()); }); }

const char* nw_version(void) { return "0.1.0"; }

const char* nw_status_name(int status) {
  switch (status) {
    case NW_OK:
      return "ok";
    case NW_ERR_INVALID_ARGUMENT:
      return "invalid_argument";
    case NW_ERR_MALFORMED:
      return "malformed";
    case NW_ERR_AUTHENTICATION_FAILED:
      return "authentication_failed";
    case NW_ERR_NOT_FOUND:
      return "not_found";
    case NW_ERR_CRYPTO:
      return "crypto";
    case NW_ERR_EXPIRED:
      return "expired";
    case NW_ERR_UNSUPPORTED:
      return "unsupported";
    case NW_ERR_INVALID_STATE:
      return "invalid_state";
    case NW_ERR_IO:
      return "io";
    case NW_ERR_CONFLICT:
      return "conflict";
    case NW_ERR_FORBIDDEN:
      return "forbidden";
    case NW_ERR_RESYNC_REQUIRED:
      return "resync_required";
    case NW_ERR_INTEGRITY:
      return "integrity";
    default:
      return "internal";
  }
}

int nw_facet_tag(const char* facet_name, uint32_t* tag) {
  if (facet_name == nullptr || tag == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    if (std::string_view(facet_name) == kDefaultFacetName) {
      *tag = kDefaultFacetTag;
      return kOk;
    }
    *tag = facetTagForName(facet_name);
    return kOk;
  });
}

int nw_buffer_set(nw_buffer* buffer, const uint8_t* data, size_t length) {
  if (buffer == nullptr || (data == nullptr && length > 0)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return fillBuffer(buffer, viewOfInput(data, length), false); });
}

void nw_buffer_free(nw_buffer* buffer) {
  if (buffer == nullptr || buffer->data == nullptr) {
    return;
  }
  if (buffer->secret != 0) {
    sodium_free(buffer->data);
  } else {
    std::free(buffer->data);
  }
  clearBuffer(buffer);
}

/* ---- Keystore ---- */

int nw_keystore_create_callbacks(const nw_keystore_callbacks* callbacks, nw_keystore** out) {
  if (callbacks == nullptr || out == nullptr || callbacks->wrap == nullptr || callbacks->unwrap == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    nw_keystore_callbacks host = *callbacks;
    KeystoreCallbacks adapted;
    adapted.backendName = textOrEmpty(host.backend_name);
    auto invoke = [host](auto function, ByteView input, ByteView label) -> Result<Bytes> {
      nw_buffer produced;
      clearBuffer(&produced);
      int status = function(host.user, input.data(), input.size(), label.data(), label.size(), &produced);
      if (status != NW_OK) {
        return static_cast<Status>(status);
      }
      Bytes copy(produced.data, produced.data + produced.length);
      nw_buffer_free(&produced);
      return copy;
    };
    adapted.wrap = [invoke, host](ByteView secret, ByteView label) { return invoke(host.wrap, secret, label); };
    adapted.unwrap = [invoke, host](ByteView wrapped, ByteView label) { return invoke(host.unwrap, wrapped, label); };
    *out = new nw_keystore{makeCallbackKeystore(std::move(adapted))};
    return kOk;
  });
}

int nw_keystore_create_ephemeral(nw_keystore** out) {
  if (out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    *out = new nw_keystore{makeEphemeralKeystore()};
    return kOk;
  });
}

int nw_keystore_create_platform(const char* application_id, const char* data_directory, nw_keystore** out) {
  if (application_id == nullptr || data_directory == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
#if defined(__linux__) && !defined(__ANDROID__) && !defined(__EMSCRIPTEN__)
  return guarded([&] {
    *out = new nw_keystore{makeLinuxKeystore(application_id, data_directory)};
    return kOk;
  });
#else
  return NW_ERR_UNSUPPORTED;
#endif
}

int nw_keystore_backend_name(nw_keystore* keystore, nw_buffer* name) {
  if (keystore == nullptr || name == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Status probed = keystore->value->probe();
    if (probed != Status::Ok) {
      return code(probed);
    }
    return fillText(name, keystore->value->backendName());
  });
}

void nw_keystore_free(nw_keystore* keystore) { delete keystore; }

/* ---- Install ---- */

int nw_install_create(nw_install** out) {
  if (out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Install> install = createInstall();
    if (!install.ok()) {
      return code(install.status());
    }
    *out = new nw_install{install.take()};
    return kOk;
  });
}

int nw_install_seal(const nw_install* install, nw_keystore* keystore, nw_buffer* persisted) {
  if (install == nullptr || keystore == nullptr || persisted == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Bytes> sealed = sealInstall(install->value, *keystore->value);
    if (!sealed.ok()) {
      return code(sealed.status());
    }
    return fillBuffer(persisted, sealed.value(), false);
  });
}

int nw_install_open(const uint8_t* persisted, size_t length, nw_keystore* keystore, nw_install** out) {
  if (persisted == nullptr || keystore == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Install> install = openInstall(ByteView(persisted, length), *keystore->value);
    if (!install.ok()) {
      return code(install.status());
    }
    *out = new nw_install{install.take()};
    return kOk;
  });
}

int nw_install_describe(const nw_install* install, nw_buffer* json) {
  if (install == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return fillJson(json, installDescription(install->value)); });
}

int nw_install_export_secrets(const nw_install* install, nw_buffer* secrets) {
  if (install == nullptr || secrets == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    SecretBytes joined(kEncSecretBytes + kSignSecretBytes + kKeyBytes);
    std::memcpy(joined.data(), install->value.encSecret.data(), kEncSecretBytes);
    std::memcpy(joined.data() + kEncSecretBytes, install->value.signSecret.data(), kSignSecretBytes);
    std::memcpy(joined.data() + kEncSecretBytes + kSignSecretBytes, install->value.storeKey.data(), kKeyBytes);
    return fillBuffer(secrets, joined.view(), true);
  });
}

int nw_install_import(const char* install_id, const uint8_t* enc_pub, const uint8_t* sign_pub,
                      const uint8_t* secrets, size_t secrets_length, nw_install** out) {
  if (install_id == nullptr || enc_pub == nullptr || sign_pub == nullptr || secrets == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    SecretBytes secretBytes{ByteView(secrets, secrets_length)};
    Result<Install> install = restoreInstall(install_id, ByteView(enc_pub, kPublicKeyBytes),
                                             ByteView(sign_pub, kPublicKeyBytes), secretBytes);
    if (!install.ok()) {
      return code(install.status());
    }
    *out = new nw_install{install.take()};
    return kOk;
  });
}

void nw_install_free(nw_install* install) { delete install; }

/* ---- Account ---- */

int nw_account_auth_key(const uint8_t* password, size_t password_length, const char* params_json,
                        nw_buffer* auth_key_base64url) {
  if (password == nullptr || params_json == nullptr || auth_key_base64url == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<PwhashParameters> parameters = parsePwhashParameters(params_json);
    if (!parameters.ok()) {
      return code(parameters.status());
    }
    Result<PasswordKeys> keys = derivePasswordKeys(ByteView(password, password_length), parameters.value());
    if (!keys.ok()) {
      return code(keys.status());
    }
    return fillText(auth_key_base64url, toBase64Url(keys.value().authKey.view()));
  });
}

int nw_account_create(const char* user_id, const uint8_t* password, size_t password_length,
                      const char* params_json, nw_account** out, nw_buffer* bundle_json,
                      nw_buffer* recovery_entropy, nw_buffer* auth_key_base64url) {
  bool valid = user_id != nullptr && password != nullptr && params_json != nullptr && out != nullptr &&
               bundle_json != nullptr && recovery_entropy != nullptr && auth_key_base64url != nullptr;
  if (!valid) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<PwhashParameters> parameters = parsePwhashParameters(params_json);
    if (!parameters.ok()) {
      return code(parameters.status());
    }
    Result<Account::Created> created =
        Account::create(user_id, ByteView(password, password_length), parameters.value());
    if (!created.ok()) {
      return code(created.status());
    }
    int status = fillJson(bundle_json, keyBundleToJson(created.value().bundle));
    if (status == NW_OK) {
      status = fillBuffer(recovery_entropy, created.value().recoveryEntropy.view(), true);
    }
    if (status == NW_OK) {
      status = fillText(auth_key_base64url, toBase64Url(created.value().authKey.view()));
    }
    if (status != NW_OK) {
      return status;
    }
    *out = new nw_account{std::move(created.value().account)};
    return kOk;
  });
}

int nw_account_unlock_password(const char* bundle_json, const uint8_t* password, size_t password_length,
                               const char* params_json, nw_account** out) {
  if (bundle_json == nullptr || password == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<KeyBundle> bundle = parseBundle(bundle_json);
    if (!bundle.ok()) {
      return code(Status::Malformed);
    }
    Result<PwhashParameters> parameters = bundleOrExplicitParameters(bundle.value(), params_json);
    if (!parameters.ok()) {
      return code(Status::Malformed);
    }
    return publishAccount(Account::unlockWithPassword(bundle.value(), ByteView(password, password_length),
                                                      parameters.value()),
                          out);
  });
}

int nw_account_unlock_recovery(const char* bundle_json, const uint8_t* recovery_entropy, size_t length,
                               nw_account** out) {
  if (bundle_json == nullptr || recovery_entropy == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<KeyBundle> bundle = parseBundle(bundle_json);
    Result<SymmetricKey> entropy = SymmetricKey::fromBytes(ByteView(recovery_entropy, length));
    if (!bundle.ok() || !entropy.ok()) {
      return code(Status::Malformed);
    }
    return publishAccount(Account::unlockWithRecovery(bundle.value(), entropy.value()), out);
  });
}

int nw_account_unlock_amk(const char* bundle_json, const uint8_t* amk, size_t length, nw_account** out) {
  if (bundle_json == nullptr || amk == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<KeyBundle> bundle = parseBundle(bundle_json);
    Result<SymmetricKey> key = SymmetricKey::fromBytes(ByteView(amk, length));
    if (!bundle.ok() || !key.ok()) {
      return code(Status::Malformed);
    }
    return publishAccount(Account::unlockWithAmk(bundle.value(), key.take()), out);
  });
}

int nw_account_export_amk(const nw_account* account, nw_buffer* amk) {
  if (account == nullptr || amk == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return fillBuffer(amk, account->value.amk().view(), true); });
}

int nw_account_seal_amk(const nw_account* account, const uint8_t* recipient_pub, size_t length,
                        nw_buffer* sealed) {
  if (account == nullptr || recipient_pub == nullptr || sealed == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Bytes> result = account->value.sealAmkTo(ByteView(recipient_pub, length));
    if (!result.ok()) {
      return code(result.status());
    }
    return fillBuffer(sealed, result.value(), false);
  });
}

int nw_account_identity(const nw_account* account, nw_buffer* json) {
  if (account == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return fillJson(json, publicIdentityToJson(account->value.publicIdentity())); });
}

void nw_account_free(nw_account* account) { delete account; }

int nw_renewal_key_create(nw_buffer* public_key, nw_buffer* secret_key) {
  if (public_key == nullptr || secret_key == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    SignKeypair keypair = generateSignKeypair();
    int status = fillBuffer(public_key, keypair.publicKey, false);
    if (status != kOk) {
      return status;
    }
    return fillBuffer(secret_key, keypair.secretKey.view(), true);
  });
}

int nw_account_sign_renewal_certificate(const nw_account* account, const uint8_t* renewal_bytes,
                                        size_t renewal_length, nw_buffer* signature) {
  if (account == nullptr || renewal_bytes == nullptr || signature == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Bytes> signature_ = signRenewalCertificate(account->value.signSecret().view(),
                                                   viewOfInput(renewal_bytes, renewal_length));
    if (!signature_.ok()) {
      return code(signature_.status());
    }
    return fillBuffer(signature, signature_.value(), false);
  });
}

int nw_renewal_renew_certificate(const uint8_t* renewal_secret, size_t secret_length, const char* renewal_cert_id,
                                 const uint8_t* current_certificate, size_t current_length, int64_t now_unix_seconds,
                                 int64_t lifetime_seconds, int64_t renewal_expires_unix_seconds, nw_buffer* body_json) {
  bool complete = renewal_secret != nullptr && renewal_cert_id != nullptr && current_certificate != nullptr &&
                  body_json != nullptr;
  if (!complete) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<RenewedCertificate> renewed =
        renewDelegationCertificate(viewOfInput(renewal_secret, secret_length), renewal_cert_id,
                                   viewOfInput(current_certificate, current_length), now_unix_seconds,
                                   lifetime_seconds, renewal_expires_unix_seconds);
    if (!renewed.ok()) {
      return code(renewed.status());
    }
    Json body = Json::object();
    body["certificate"] = toBase64Url(renewed.value().certificateBytes);
    body["certificateSignature"] = toBase64Url(renewed.value().signature);
    return fillJson(body_json, body);
  });
}

int nw_recovery_words_encode(const uint8_t* entropy, size_t length, nw_buffer* words) {
  if (entropy == nullptr || words == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<std::vector<std::string>> encoded = recoveryEntropyToWords(viewOfInput(entropy, length));
    if (!encoded.ok()) {
      return code(encoded.status());
    }
    std::string text;
    for (const std::string& word : encoded.value()) {
      if (!text.empty()) {
        text += " ";
      }
      text += word;
    }
    return fillBuffer(words, viewOf(text), true);
  });
}

int nw_recovery_words_decode(const char* words, nw_buffer* entropy) {
  if (words == nullptr || entropy == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Bytes> decoded = parseRecoveryWords(words);
    if (!decoded.ok()) {
      return code(decoded.status());
    }
    return fillBuffer(entropy, decoded.value(), true);
  });
}

int nw_contact_code_normalize(const char* contact_code, nw_buffer* canonical) {
  if (contact_code == nullptr || canonical == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<std::string> normalized = normalizeContactCode(contact_code);
    if (!normalized.ok()) {
      return code(normalized.status());
    }
    return fillText(canonical, normalized.value());
  });
}

#if defined(NW_ENABLE_TEST_HOOKS)
int nw_testing_set_random_script(const uint8_t* script, size_t length) {
  if (script == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  testing::setRandomScript(ByteView(script, length));
  return kOk;
}

int nw_testing_restore_random(void) {
  testing::restoreSystemRandom();
  return kOk;
}
#endif

}  // extern "C"
