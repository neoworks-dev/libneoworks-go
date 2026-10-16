#include "key_history.hpp"

#include <sodium.h>

#include "tlv.hpp"

namespace nw {

namespace {

constexpr size_t kEpochBytes = 4;
constexpr size_t kEntryBytes = kEpochBytes + kKeyBytes;

void appendEpoch(Bytes& destination, uint32_t epoch) {
  destination.push_back(static_cast<uint8_t>(epoch >> 24));
  destination.push_back(static_cast<uint8_t>(epoch >> 16));
  destination.push_back(static_cast<uint8_t>(epoch >> 8));
  destination.push_back(static_cast<uint8_t>(epoch));
}

}  // namespace

Bytes encodeKeyHistory(const KeyHistory& history) {
  Bytes encoded;
  encoded.reserve(history.size() * kEntryBytes);
  for (const auto& [epoch, key] : history) {
    appendEpoch(encoded, epoch);
    appendTo(encoded, key.view());
  }
  return encoded;
}

Result<KeyHistory> decodeKeyHistory(ByteView plaintext) {
  if (plaintext.size() % kEntryBytes != 0) {
    return Status::Malformed;
  }
  KeyHistory history;
  for (size_t offset = 0; offset < plaintext.size(); offset += kEntryBytes) {
    uint32_t epoch = decodeU32(plaintext.subspan(offset, kEpochBytes)).value();
    if (!history.empty() && epoch <= history.back().first) {
      return Status::Malformed;
    }
    Result<SymmetricKey> key = SymmetricKey::fromBytes(plaintext.subspan(offset + kEpochBytes, kKeyBytes));
    if (!key.ok()) {
      return key.status();
    }
    history.emplace_back(epoch, key.take());
  }
  return history;
}

Result<KeyHistory> previousNodeKeys(const Node& node, const SymmetricKey& nodeKey) {
  Result<Bytes> plaintext = decryptFacet(facetKey(nodeKey, kKeyHistoryFacet), node, kKeyHistoryFacet);
  if (plaintext.status() == Status::NotFound) {
    return KeyHistory();
  }
  if (!plaintext.ok()) {
    return plaintext.status();
  }
  Result<KeyHistory> history = decodeKeyHistory(plaintext.value());
  sodium_memzero(plaintext.value().data(), plaintext.value().size());
  return history;
}

Status appendKeyHistory(FacetMap& plaintexts, uint32_t oldEpoch, const SymmetricKey& oldKey) {
  KeyHistory history;
  auto stored = plaintexts.find(kKeyHistoryFacet);
  if (stored != plaintexts.end()) {
    Result<KeyHistory> decoded = decodeKeyHistory(stored->second);
    if (!decoded.ok()) {
      return decoded.status();
    }
    history = decoded.take();
    sodium_memzero(stored->second.data(), stored->second.size());
  }
  if (!history.empty() && oldEpoch <= history.back().first) {
    return Status::Malformed;
  }
  history.emplace_back(oldEpoch, oldKey.clone());
  plaintexts[kKeyHistoryFacet] = encodeKeyHistory(history);
  return Status::Ok;
}

}  // namespace nw
