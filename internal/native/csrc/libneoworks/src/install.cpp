#include "install.hpp"

#include <sodium.h>

#include <cstring>

#include "tlv.hpp"

namespace nw {

namespace {

constexpr uint32_t kInstallFormatVersion = 1;
constexpr size_t kInstallSecretBytes = kEncSecretBytes + kSignSecretBytes + kKeyBytes;

Bytes secretsLabel(const Install& install) {
  return TlvWriter("nw-install-secrets-v1").text(install.installId).bytes(install.encPub).bytes(install.signPub).finish();
}

SecretBytes joinInstallSecrets(const Install& install) {
  SecretBytes joined(kInstallSecretBytes);
  std::memcpy(joined.data(), install.encSecret.data(), kEncSecretBytes);
  std::memcpy(joined.data() + kEncSecretBytes, install.signSecret.data(), kSignSecretBytes);
  std::memcpy(joined.data() + kEncSecretBytes + kSignSecretBytes, install.storeKey.data(), kKeyBytes);
  return joined;
}

Status restoreInstallSecrets(const SecretBytes& joined, Install& install) {
  if (joined.size() != kInstallSecretBytes) {
    return Status::Malformed;
  }
  install.encSecret = SecretBytes(joined.view().subspan(0, kEncSecretBytes));
  install.signSecret = SecretBytes(joined.view().subspan(kEncSecretBytes, kSignSecretBytes));
  Result<SymmetricKey> storeKey = SymmetricKey::fromBytes(joined.view().subspan(kEncSecretBytes + kSignSecretBytes));
  if (!storeKey.ok()) {
    return storeKey.status();
  }
  install.storeKey = storeKey.take();
  return Status::Ok;
}

bool publicKeysMatchSecrets(const Install& install) {
  Bytes derivedEncPub(crypto_box_PUBLICKEYBYTES);
  crypto_scalarmult_base(derivedEncPub.data(), install.encSecret.data());
  Bytes derivedSignPub(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(derivedSignPub.data(), install.signSecret.data());
  return derivedEncPub == install.encPub && derivedSignPub == install.signPub;
}

}  // namespace

Result<Install> createInstall() {
  Install install;
  install.installId = newUuid();
  BoxKeypair boxKeypair = generateBoxKeypair();
  install.encPub = std::move(boxKeypair.publicKey);
  install.encSecret = std::move(boxKeypair.secretKey);
  SignKeypair signKeypair = generateSignKeypair();
  install.signPub = std::move(signKeypair.publicKey);
  install.signSecret = std::move(signKeypair.secretKey);
  install.storeKey = SymmetricKey::random();
  return install;
}

Result<Bytes> sealInstall(const Install& install, Keystore& keystore) {
  SecretBytes secrets = joinInstallSecrets(install);
  Result<Bytes> wrapped = keystore.wrapSecret(secrets.view(), secretsLabel(install));
  if (!wrapped.ok()) {
    return wrapped.status();
  }
  return TlvWriter("nw-install-file-v1")
      .u32(kInstallFormatVersion)
      .text(keystore.backendName())
      .text(install.installId)
      .bytes(install.encPub)
      .bytes(install.signPub)
      .bytes(wrapped.value())
      .finish();
}

Result<Install> restoreInstall(const std::string& installId, ByteView encPub, ByteView signPub,
                               const SecretBytes& secrets) {
  if (!isLowercaseUuid(installId) || encPub.size() != kPublicKeyBytes || signPub.size() != kPublicKeyBytes) {
    return Status::Malformed;
  }
  Install install;
  install.installId = installId;
  install.encPub.assign(encPub.begin(), encPub.end());
  install.signPub.assign(signPub.begin(), signPub.end());
  Status restored = restoreInstallSecrets(secrets, install);
  if (restored != Status::Ok) {
    return restored;
  }
  if (!publicKeysMatchSecrets(install)) {
    return Status::AuthenticationFailed;
  }
  return install;
}

Install duplicateInstall(const Install& install) {
  Install copy;
  copy.installId = install.installId;
  copy.encPub = install.encPub;
  copy.encSecret = SecretBytes(install.encSecret.view());
  copy.signPub = install.signPub;
  copy.signSecret = SecretBytes(install.signSecret.view());
  copy.storeKey = install.storeKey.clone();
  return copy;
}

Result<Install> openInstall(ByteView persisted, Keystore& keystore) {
  TlvReader reader(persisted);
  if (!reader.valid() || reader.context() != "nw-install-file-v1") {
    return Status::Malformed;
  }
  std::optional<ByteView> version = reader.nextField();
  std::optional<ByteView> backend = reader.nextField();
  std::optional<ByteView> installId = reader.nextField();
  std::optional<ByteView> encPub = reader.nextField();
  std::optional<ByteView> signPub = reader.nextField();
  std::optional<ByteView> wrapped = reader.nextField();
  bool complete = version && backend && installId && encPub && signPub && wrapped && reader.atEnd();
  if (!complete || decodeU32(*version) != kInstallFormatVersion) {
    return Status::Malformed;
  }
  std::string installIdText(reinterpret_cast<const char*>(installId->data()), installId->size());
  Install shell;
  shell.installId = installIdText;
  shell.encPub.assign(encPub->begin(), encPub->end());
  shell.signPub.assign(signPub->begin(), signPub->end());
  if (!isLowercaseUuid(installIdText) || shell.encPub.size() != kPublicKeyBytes || shell.signPub.size() != kPublicKeyBytes) {
    return Status::Malformed;
  }
  Result<SecretBytes> secrets = keystore.unwrapSecret(*wrapped, secretsLabel(shell));
  if (!secrets.ok()) {
    return secrets.status();
  }
  return restoreInstall(installIdText, shell.encPub, shell.signPub, secrets.value());
}

}  // namespace nw
