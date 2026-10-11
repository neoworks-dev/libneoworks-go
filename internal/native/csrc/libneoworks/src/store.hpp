#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "crypto.hpp"

namespace nw {

// Durable storage of opaque (kind, key) -> bytes records. Backends never see plaintext.
class RecordBackend {
 public:
  using Visitor = std::function<void(std::string_view kind, std::string_view key, ByteView value)>;

  virtual ~RecordBackend() = default;
  virtual Status put(std::string_view kind, std::string_view key, ByteView value) = 0;
  virtual Status remove(std::string_view kind, std::string_view key) = 0;
  virtual Status visitAll(const Visitor& visitor) = 0;
  virtual Status clear() = 0;
};

std::unique_ptr<RecordBackend> makeMemoryBackend();

// Host-persisted backend: used where the engine cannot reach durable storage
// itself (wasm persists to IndexedDB from the host side).
struct RecordCallbacks {
  std::function<Status(std::string_view kind, std::string_view key, ByteView value)> put;
  std::function<Status(std::string_view kind, std::string_view key)> remove;
  std::function<Status()> clear;
  // Records the host loaded before opening the engine.
  std::function<void(const RecordBackend::Visitor& visitor)> loadAll;
};
std::unique_ptr<RecordBackend> makeCallbackBackend(RecordCallbacks callbacks);

#if defined(NW_HAVE_SQLITE)
std::unique_ptr<RecordBackend> makeSqliteBackend(const std::string& path);
#endif

// Record-level AEAD over a backend. The AAD binds each ciphertext to its
// (kind, key) slot so records cannot be swapped between slots.
class EncryptedRecordStore {
 public:
  EncryptedRecordStore(std::unique_ptr<RecordBackend> backend, SymmetricKey storeKey);

  Status put(std::string_view kind, std::string_view key, ByteView plaintext);
  Status remove(std::string_view kind, std::string_view key);
  Status clear();

  using Visitor = std::function<void(std::string_view kind, std::string_view key, const Bytes& plaintext)>;
  // Records that fail authentication are skipped and counted.
  Status visitAll(const Visitor& visitor, size_t& corruptRecords);

 private:
  std::unique_ptr<RecordBackend> backend_;
  SymmetricKey storeKey_;
};

}  // namespace nw
