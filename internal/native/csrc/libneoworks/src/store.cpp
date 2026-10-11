#include "store.hpp"

#include <map>

#include "tlv.hpp"

namespace nw {

namespace {

using SlotKey = std::pair<std::string, std::string>;

class MemoryBackend : public RecordBackend {
 public:
  Status put(std::string_view kind, std::string_view key, ByteView value) override {
    records_[SlotKey(kind, key)] = Bytes(value.begin(), value.end());
    return Status::Ok;
  }

  Status remove(std::string_view kind, std::string_view key) override {
    records_.erase(SlotKey(kind, key));
    return Status::Ok;
  }

  Status visitAll(const Visitor& visitor) override {
    for (const auto& [slot, value] : records_) {
      visitor(slot.first, slot.second, value);
    }
    return Status::Ok;
  }

  Status clear() override {
    records_.clear();
    return Status::Ok;
  }

 private:
  std::map<SlotKey, Bytes> records_;
};

class CallbackBackend : public RecordBackend {
 public:
  explicit CallbackBackend(RecordCallbacks callbacks) : callbacks_(std::move(callbacks)) {}

  Status put(std::string_view kind, std::string_view key, ByteView value) override {
    return callbacks_.put(kind, key, value);
  }

  Status remove(std::string_view kind, std::string_view key) override { return callbacks_.remove(kind, key); }

  Status visitAll(const Visitor& visitor) override {
    callbacks_.loadAll(visitor);
    return Status::Ok;
  }

  Status clear() override { return callbacks_.clear(); }

 private:
  RecordCallbacks callbacks_;
};

Bytes recordAad(std::string_view kind, std::string_view key) {
  return TlvWriter("nw-record-v1").text(kind).text(key).finish();
}

}  // namespace

std::unique_ptr<RecordBackend> makeMemoryBackend() { return std::make_unique<MemoryBackend>(); }

std::unique_ptr<RecordBackend> makeCallbackBackend(RecordCallbacks callbacks) {
  return std::make_unique<CallbackBackend>(std::move(callbacks));
}

EncryptedRecordStore::EncryptedRecordStore(std::unique_ptr<RecordBackend> backend, SymmetricKey storeKey)
    : backend_(std::move(backend)), storeKey_(std::move(storeKey)) {}

Status EncryptedRecordStore::put(std::string_view kind, std::string_view key, ByteView plaintext) {
  Bytes boxed = aeadEncrypt(storeKey_, plaintext, recordAad(kind, key));
  return backend_->put(kind, key, boxed);
}

Status EncryptedRecordStore::remove(std::string_view kind, std::string_view key) {
  return backend_->remove(kind, key);
}

Status EncryptedRecordStore::clear() { return backend_->clear(); }

Status EncryptedRecordStore::visitAll(const Visitor& visitor, size_t& corruptRecords) {
  corruptRecords = 0;
  return backend_->visitAll([&](std::string_view kind, std::string_view key, ByteView value) {
    Result<Bytes> plaintext = aeadDecrypt(storeKey_, value, recordAad(kind, key));
    if (!plaintext.ok()) {
      ++corruptRecords;
      return;
    }
    visitor(kind, key, plaintext.value());
  });
}

}  // namespace nw
