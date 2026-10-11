#pragma once

#include <string>

#include "crypto.hpp"
#include "keystore.hpp"

namespace nw {

// The per-installation identity (contract section 6): ids, X25519 + Ed25519
// keypairs, and the key that encrypts the local store.
struct Install {
  std::string installId;
  Bytes encPub;
  SecretBytes encSecret;
  Bytes signPub;
  SecretBytes signSecret;
  SymmetricKey storeKey;
};

Result<Install> createInstall();

// Rebuilds an install from its public parts and the secret blob
// (encSec || signSec || storeKey), checking they belong together.
Result<Install> restoreInstall(const std::string& installId, ByteView encPub, ByteView signPub,
                               const SecretBytes& secrets);
Install duplicateInstall(const Install& install);

// Persisted form: public parts in the clear, secrets wrapped by the keystore.
Result<Bytes> sealInstall(const Install& install, Keystore& keystore);
Result<Install> openInstall(ByteView persisted, Keystore& keystore);

}  // namespace nw
