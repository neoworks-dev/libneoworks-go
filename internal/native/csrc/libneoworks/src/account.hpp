#pragma once

#include <string>

#include "crypto.hpp"
#include "json.hpp"

namespace nw {

struct PwhashParametersView {
  Bytes salt;
  uint64_t opsLimit = 0;
  uint64_t memLimit = 0;
};

// Everything GET /keys/bundle returns (contract section 7).
struct KeyBundle {
  std::string userId;
  uint32_t version = 0;
  Bytes amkPassword;
  Bytes amkRecovery;
  Bytes identityPrivate;
  Bytes encPub;
  Bytes signPub;
  Bytes selfSig;
  // Present when the server includes the account's password-hash parameters.
  std::optional<PwhashParametersView> pwhash;
};

Json keyBundleToJson(const KeyBundle& bundle);
Result<KeyBundle> keyBundleFromJson(const Json& json);

struct PasswordKeys {
  SymmetricKey authKey;
  SymmetricKey passwordKek;
};

Result<PasswordKeys> derivePasswordKeys(ByteView password, const PwhashParameters& parameters);
SymmetricKey deriveRecoveryKek(const SymmetricKey& recoveryEntropy);

Bytes amkWrapAad(std::string_view userId, std::string_view purpose);
Bytes identityPrivateAad(std::string_view userId, uint32_t bundleVersion);
Bytes identitySelfSignatureMessage(std::string_view userId, ByteView encPub, ByteView signPub);

// Public identity of a user, as served by GET /keys/identity.
struct PublicIdentity {
  std::string userId;
  Bytes encPub;
  Bytes signPub;
  Bytes selfSig;
  uint32_t version = 0;
};

Json publicIdentityToJson(const PublicIdentity& identity);
Result<PublicIdentity> publicIdentityFromJson(const Json& json);
// Checks the self-signature; pinning is the caller's decision.
Status verifyPublicIdentity(const PublicIdentity& identity);

class Account {
 public:
  const std::string& userId() const { return userId_; }
  uint32_t bundleVersion() const { return bundleVersion_; }
  const SymmetricKey& amk() const { return amk_; }
  ByteView encPub() const { return encPub_; }
  const SecretBytes& encSecret() const { return encSecret_; }
  ByteView signPub() const { return signPub_; }
  const SecretBytes& signSecret() const { return signSecret_; }

  PublicIdentity publicIdentity() const;

  struct Created;
  static Result<Created> create(std::string userId, ByteView password, const PwhashParameters& parameters);
  static Result<Created> createWithPasswordKeys(std::string userId, PasswordKeys passwordKeys);
  static Result<Account> unlockWithPassword(const KeyBundle& bundle, ByteView password,
                                            const PwhashParameters& parameters);
  static Result<Account> unlockWithPasswordKek(const KeyBundle& bundle, const SymmetricKey& passwordKek);
  static Result<Account> unlockWithRecovery(const KeyBundle& bundle, const SymmetricKey& recoveryEntropy);
  static Result<Account> unlockWithAmk(const KeyBundle& bundle, SymmetricKey amk);

  // Rotation: fresh AMK, same identity, bundleVersion + 1.
  struct Rotated;
  Result<Rotated> rotate(const SymmetricKey& passwordKek, const SymmetricKey& recoveryKek) const;

  Result<Bytes> sealAmkTo(ByteView recipientEncPub) const;
  Account duplicate() const;
  // Key that encrypts this account's local store.
  SymmetricKey storeKey() const;

 private:
  Result<KeyBundle> buildBundle(const SymmetricKey& passwordKek, const SymmetricKey& recoveryKek) const;

  std::string userId_;
  uint32_t bundleVersion_ = 0;
  SymmetricKey amk_;
  Bytes encPub_;
  SecretBytes encSecret_;
  Bytes signPub_;
  SecretBytes signSecret_;
  Bytes selfSig_;
};

struct Account::Created {
  Account account;
  KeyBundle bundle;
  SymmetricKey recoveryEntropy;
  SymmetricKey authKey;
};

struct Account::Rotated {
  Account account;
  KeyBundle bundle;
};

}  // namespace nw
