#pragma once

#include <utility>
#include <vector>

#include "node.hpp"
#include "wire.hpp"

namespace nw {

// The content facet holding a node's previous keys, encrypted under its current key like any
// facet. Named facets derive tags below kMaxOrdinal, so no schema can claim it.
constexpr uint32_t kKeyHistoryFacet = wire::kMaxOrdinal;

// A node's earlier keys by epoch, oldest first.
using KeyHistory = std::vector<std::pair<uint32_t, SymmetricKey>>;

// Each entry as a big-endian u32 epoch followed by the 32-byte key.
Bytes encodeKeyHistory(const KeyHistory& history);
// Malformed unless whole entries with strictly ascending epochs.
Result<KeyHistory> decodeKeyHistory(ByteView plaintext);

// The history in `node`'s content, opened with its key at its current epoch; empty when the node
// never changed key.
Result<KeyHistory> previousNodeKeys(const Node& node, const SymmetricKey& nodeKey);

// `plaintexts` with the key-history facet extended by `oldKey` at `oldEpoch`, for sealing the
// node under its next key.
Status appendKeyHistory(FacetMap& plaintexts, uint32_t oldEpoch, const SymmetricKey& oldKey);

}  // namespace nw
