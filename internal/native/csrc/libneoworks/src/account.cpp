#include "account.hpp"

#include <sodium.h>

#include <cstring>

#include "tlv.hpp"

namespace nw {

namespace {

constexpr std::string_view kAuthContext = "nwauth01";
constexpr std::string_view kRecoveryContext = "nwrecov1";
constexpr size_t kIdentityPrivateBytes = kEncSecretBytes + kSignSecretBytes;


}  // namespace

Json keyBundleToJson(const KeyBundle& bundle) {
  Json json = Json::object();
  json["userId"] = bundle.userId;
  json["version"] = bundle.version;
  json["amkPassword"] = bytesToJson(bundle.amkPassword);
  json["amkRecovery"] = bytesToJson(bundle.amkRecovery);
  json["identityPrivate"] = bytesToJson(bundle.identityPrivate);
  json["encPub"] = bytesToJson(bundle.encPub);
  json["signPub"] = bytesToJson(bundle.signPub);
  json["selfSig"] = bytesToJson(bundle.selfSig);
  if (bundle.pwhash.has_value()) {
    json["pwhashSalt"] = bytesToJson(bundle.pwhash->salt);
    json["pwhashOps"] = bundle.pwhash->opsLimit;
    json["pwhashMem"] = bundle.pwhash->memLimit;
  }
  return json;
}

Result<KeyBundle> keyBundleFromJson(const Json& json) {
  std::optional<std::string> userId = readString(json, "userId");
  std::optional<uint64_t> version = readUnsigned(json, "version");
  std::optional<Bytes> amkPassword = readBytes(json, "amkPassword");
  std::optional<Bytes> amkRecovery = readBytes(json, "amkRecovery");
  std::optional<Bytes> identityPrivate = readBytes(json, "identityPrivate");
  std::optional<Bytes> encPub = readBytes(json, "encPub");
  std::optional<Bytes> signPub = readBytes(json, "signPub");
  std::optional<Bytes> selfSig = readBytes(json, "selfSig");
  bool complete = userId && version && amkPassword && amkRecovery && identityPrivate && encPub && signPub &&
                  selfSig;
  if (!complete || !isLowercaseUuid(*userId) || *version > UINT32_MAX) {
    return Status::Malformed;
  }
  KeyBundle bundle;
  bundle.userId = *userId;
  bundle.version = static_cast<uint32_t>(*version);
  bundle.amkPassword = std::move(*amkPassword);
  bundle.amkRecovery = std::move(*amkRecovery);
  bundle.identityPrivate = std::move(*identityPrivate);
  bundle.encPub = std::move(*encPub);
  bundle.signPub = std::move(*signPub);
  bundle.selfSig = std::move(*selfSig);
  std::optional<Bytes> salt = readBytes(json, "pwhashSalt");
  std::optional<uint64_t> ops = readUnsigned(json, "pwhashOps");
  std::optional<uint64_t> mem = readUnsigned(json, "pwhashMem");
  if (salt && ops && mem) {
    bundle.pwhash = PwhashParametersView{std::move(*salt), *ops, *mem};
  }
  return bundle;
}

Json publicIdentityToJson(const PublicIdentity& identity) {
  Json json = Json::object();
  json["userId"] = identity.userId;
  json["encPub"] = bytesToJson(identity.encPub);
  json["signPub"] = bytesToJson(identity.signPub);
  json["selfSig"] = bytesToJson(identity.selfSig);
  json["version"] = identity.version;
  return json;
}

Result<PublicIdentity> publicIdentityFromJson(const Json& json) {
  std::optional<std::string> userId = readString(json, "userId");
  std::optional<Bytes> encPub = readBytes(json, "encPub");
  std::optional<Bytes> signPub = readBytes(json, "signPub");
  std::optional<Bytes> selfSig = readBytes(json, "selfSig");
  std::optional<uint64_t> version = readUnsigned(json, "version");
  bool complete = userId && encPub && signPub && selfSig && version;
  if (!complete || !isLowercaseUuid(*userId) || *version > UINT32_MAX) {
    return Status::Malformed;
  }
  PublicIdentity identity;
  identity.userId = *userId;
  identity.encPub = std::move(*encPub);
  identity.signPub = std::move(*signPub);
  identity.selfSig = std::move(*selfSig);
  identity.version = static_cast<uint32_t>(*version);
  return identity;
}

Result<PasswordKeys> derivePasswordKeys(ByteView password, const PwhashParameters& parameters) {
  Result<SymmetricKey> root = passwordHash(password, parameters);
  if (!root.ok()) {
    return root.status();
  }
  PasswordKeys keys;
  keys.authKey = kdf(root.value(), 1, kAuthContext);
  keys.passwordKek = kdf(root.value(), 2, kAuthContext);
  return keys;
}

SymmetricKey deriveRecoveryKek(const SymmetricKey& recoveryEntropy) {
  return kdf(recoveryEntropy, 1, kRecoveryContext);
}

Bytes amkWrapAad(std::string_view userId, std::string_view purpose) {
  return TlvWriter("nw-amk-v1").text(userId).text(purpose).finish();
}

Bytes identityPrivateAad(std::string_view userId, uint32_t bundleVersion) {
  return TlvWriter("nw-identity-v1").text(userId).u32(bundleVersion).finish();
}

Bytes identitySelfSignatureMessage(std::string_view userId, ByteView encPub, ByteView signPub) {
  return TlvWriter("nw-identity-pub-v1").text(userId).bytes(encPub).bytes(signPub).finish();
}

Status verifyPublicIdentity(const PublicIdentity& identity) {
  if (identity.encPub.size() != kPublicKeyBytes || identity.signPub.size() != kPublicKeyBytes) {
    return Status::Malformed;
  }
  Bytes message = identitySelfSignatureMessage(identity.userId, identity.encPub, identity.signPub);
  if (!verifySignature(identity.signPub, message, identity.selfSig)) {
    return Status::AuthenticationFailed;
  }
  return Status::Ok;
}

namespace {

struct OpenedIdentity {
  Bytes encPub;
  SecretBytes encSecret;
  Bytes signPub;
  SecretBytes signSecret;
};

Result<OpenedIdentity> splitIdentityPrivate(const SecretBytes& plaintext) {
  if (plaintext.size() != kIdentityPrivateBytes) {
    return Status::Malformed;
  }
  OpenedIdentity identity;
  identity.encSecret = SecretBytes(plaintext.view().subspan(0, kEncSecretBytes));
  identity.signSecret = SecretBytes(plaintext.view().subspan(kEncSecretBytes, kSignSecretBytes));
  identity.encPub.resize(crypto_box_PUBLICKEYBYTES);
  crypto_scalarmult_base(identity.encPub.data(), identity.encSecret.data());
  identity.signPub.resize(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(identity.signPub.data(), identity.signSecret.data());
  return identity;
}

// The server cannot swap public keys: they must match the keys derived from the
// decrypted secrets and carry a valid self-signature.
Status checkIdentityMatchesBundle(const OpenedIdentity& identity, const KeyBundle& bundle) {
  if (identity.encPub != bundle.encPub || identity.signPub != bundle.signPub) {
    return Status::AuthenticationFailed;
  }
  PublicIdentity publicIdentity;
  publicIdentity.userId = bundle.userId;
  publicIdentity.encPub = bundle.encPub;
  publicIdentity.signPub = bundle.signPub;
  publicIdentity.selfSig = bundle.selfSig;
  return verifyPublicIdentity(publicIdentity);
}

Result<OpenedIdentity> openIdentity(const KeyBundle& bundle, const SymmetricKey& amk) {
  Bytes associatedData = identityPrivateAad(bundle.userId, bundle.version);
  Result<SecretBytes> plaintext = aeadDecryptSecret(amk, bundle.identityPrivate, associatedData);
  if (!plaintext.ok()) {
    return plaintext.status();
  }
  Result<OpenedIdentity> identity = splitIdentityPrivate(plaintext.value());
  if (!identity.ok()) {
    return identity.status();
  }
  Status consistent = checkIdentityMatchesBundle(identity.value(), bundle);
  if (consistent != Status::Ok) {
    return consistent;
  }
  return identity;
}

SecretBytes joinIdentitySecrets(const SecretBytes& encSecret, const SecretBytes& signSecret) {
  SecretBytes joined(kIdentityPrivateBytes);
  std::memcpy(joined.data(), encSecret.data(), kEncSecretBytes);
  std::memcpy(joined.data() + kEncSecretBytes, signSecret.data(), kSignSecretBytes);
  return joined;
}

}  // namespace

PublicIdentity Account::publicIdentity() const {
  PublicIdentity identity;
  identity.userId = userId_;
  identity.encPub = encPub_;
  identity.signPub = signPub_;
  identity.selfSig = selfSig_;
  identity.version = bundleVersion_;
  return identity;
}

Result<KeyBundle> Account::buildBundle(const SymmetricKey& passwordKek, const SymmetricKey& recoveryKek) const {
  KeyBundle bundle;
  bundle.userId = userId_;
  bundle.version = bundleVersion_;
  bundle.amkPassword = aeadEncrypt(passwordKek, amk_.view(), amkWrapAad(userId_, "password"));
  bundle.amkRecovery = aeadEncrypt(recoveryKek, amk_.view(), amkWrapAad(userId_, "recovery"));
  SecretBytes identitySecrets = joinIdentitySecrets(encSecret_, signSecret_);
  bundle.identityPrivate = aeadEncrypt(amk_, identitySecrets.view(), identityPrivateAad(userId_, bundleVersion_));
  bundle.encPub = encPub_;
  bundle.signPub = signPub_;
  bundle.selfSig = selfSig_;
  return bundle;
}

Result<Account::Created> Account::create(std::string userId, ByteView password,
                                         const PwhashParameters& parameters) {
  Result<PasswordKeys> passwordKeys = derivePasswordKeys(password, parameters);
  if (!passwordKeys.ok()) {
    return passwordKeys.status();
  }
  return createWithPasswordKeys(std::move(userId), passwordKeys.take());
}

Result<Account::Created> Account::createWithPasswordKeys(std::string userId, PasswordKeys passwordKeys) {
  if (!isLowercaseUuid(userId)) {
    return Status::InvalidArgument;
  }
  Created created;
  created.recoveryEntropy = SymmetricKey::random();
  created.authKey = std::move(passwordKeys.authKey);

  Account& account = created.account;
  account.userId_ = std::move(userId);
  account.bundleVersion_ = 1;
  account.amk_ = SymmetricKey::random();
  BoxKeypair boxKeypair = generateBoxKeypair();
  account.encPub_ = std::move(boxKeypair.publicKey);
  account.encSecret_ = std::move(boxKeypair.secretKey);
  SignKeypair signKeypair = generateSignKeypair();
  account.signPub_ = std::move(signKeypair.publicKey);
  account.signSecret_ = std::move(signKeypair.secretKey);
  Bytes selfSigMessage = identitySelfSignatureMessage(account.userId_, account.encPub_, account.signPub_);
  Result<Bytes> selfSig = sign(account.signSecret_.view(), selfSigMessage);
  if (!selfSig.ok()) {
    return selfSig.status();
  }
  account.selfSig_ = selfSig.take();

  SymmetricKey recoveryKek = deriveRecoveryKek(created.recoveryEntropy);
  Result<KeyBundle> bundle = account.buildBundle(passwordKeys.passwordKek, recoveryKek);
  if (!bundle.ok()) {
    return bundle.status();
  }
  created.bundle = bundle.take();
  return created;
}

Result<Account> Account::unlockWithAmk(const KeyBundle& bundle, SymmetricKey amk) {
  Result<OpenedIdentity> identity = openIdentity(bundle, amk);
  if (!identity.ok()) {
    return identity.status();
  }
  Account account;
  account.userId_ = bundle.userId;
  account.bundleVersion_ = bundle.version;
  account.amk_ = std::move(amk);
  account.encPub_ = std::move(identity.value().encPub);
  account.encSecret_ = std::move(identity.value().encSecret);
  account.signPub_ = std::move(identity.value().signPub);
  account.signSecret_ = std::move(identity.value().signSecret);
  account.selfSig_ = bundle.selfSig;
  return account;
}

Result<Account> Account::unlockWithPasswordKek(const KeyBundle& bundle, const SymmetricKey& passwordKek) {
  Result<SymmetricKey> amk = aeadDecryptKey(passwordKek, bundle.amkPassword, amkWrapAad(bundle.userId, "password"));
  if (!amk.ok()) {
    return amk.status();
  }
  return unlockWithAmk(bundle, amk.take());
}

Result<Account> Account::unlockWithPassword(const KeyBundle& bundle, ByteView password,
                                            const PwhashParameters& parameters) {
  Result<PasswordKeys> passwordKeys = derivePasswordKeys(password, parameters);
  if (!passwordKeys.ok()) {
    return passwordKeys.status();
  }
  return unlockWithPasswordKek(bundle, passwordKeys.value().passwordKek);
}

Result<Account> Account::unlockWithRecovery(const KeyBundle& bundle, const SymmetricKey& recoveryEntropy) {
  SymmetricKey recoveryKek = deriveRecoveryKek(recoveryEntropy);
  Result<SymmetricKey> amk = aeadDecryptKey(recoveryKek, bundle.amkRecovery, amkWrapAad(bundle.userId, "recovery"));
  if (!amk.ok()) {
    return amk.status();
  }
  return unlockWithAmk(bundle, amk.take());
}

Result<Account::Rotated> Account::rotate(const SymmetricKey& passwordKek, const SymmetricKey& recoveryKek) const {
  Rotated rotated;
  Account& next = rotated.account;
  next.userId_ = userId_;
  next.bundleVersion_ = bundleVersion_ + 1;
  next.amk_ = SymmetricKey::random();
  next.encPub_ = encPub_;
  next.encSecret_ = SecretBytes(encSecret_.view());
  next.signPub_ = signPub_;
  next.signSecret_ = SecretBytes(signSecret_.view());
  next.selfSig_ = selfSig_;
  Result<KeyBundle> bundle = next.buildBundle(passwordKek, recoveryKek);
  if (!bundle.ok()) {
    return bundle.status();
  }
  rotated.bundle = bundle.take();
  return rotated;
}

Account Account::duplicate() const {
  Account copy;
  copy.userId_ = userId_;
  copy.bundleVersion_ = bundleVersion_;
  copy.amk_ = amk_.clone();
  copy.encPub_ = encPub_;
  copy.encSecret_ = SecretBytes(encSecret_.view());
  copy.signPub_ = signPub_;
  copy.signSecret_ = SecretBytes(signSecret_.view());
  copy.selfSig_ = selfSig_;
  return copy;
}

SymmetricKey Account::storeKey() const { return kdf(amk_, 3, "nwstore1"); }

Result<Bytes> Account::sealAmkTo(ByteView recipientEncPub) const { return seal(recipientEncPub, amk_.view()); }

}  // namespace nw
