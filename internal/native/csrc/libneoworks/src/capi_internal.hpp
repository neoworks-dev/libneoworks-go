#pragma once

#include <sodium.h>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "../include/neoworks.h"
#include "account.hpp"
#include "blob.hpp"
#include "client.hpp"
#include "install.hpp"
#include "keystore.hpp"
#include "link.hpp"
#include "sync.hpp"
#include "tlv.hpp"

struct nw_keystore {
  std::unique_ptr<nw::Keystore> value;
};
struct nw_install {
  nw::Install value;
};
struct nw_account {
  nw::Account value;
};
struct nw_client {
  std::unique_ptr<nw::Client> value;
};
struct nw_sync {
  std::unique_ptr<nw::SyncSession> value;
};
struct nw_blob_transfer {
  std::unique_ptr<nw::BlobTransfer> value;
};
struct nw_link_reader {
  std::unique_ptr<nw::LinkReader> value;
};

namespace nw::capi {

inline constexpr int kOk = 0;

inline int code(Status status) { return static_cast<int>(status); }

// No exception may cross the C boundary.
template <typename Operation>
int guarded(Operation operation) noexcept {
  try {
    return operation();
  } catch (...) {
    return NW_ERR_INTERNAL;
  }
}

void clearBuffer(nw_buffer* buffer);
int fillBuffer(nw_buffer* out, ByteView data, bool secret);
int fillText(nw_buffer* out, const std::string& text);
int fillJson(nw_buffer* out, const Json& json);

std::optional<Json> parseText(const char* text);
ByteView viewOfInput(const uint8_t* data, size_t length);
std::string textOrEmpty(const char* text);

}  // namespace nw::capi
