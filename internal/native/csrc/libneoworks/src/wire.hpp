#pragma once

#include <cstdint>

#include "bytes.hpp"
#include "status.hpp"

// The OpenSchema wire format (openschema docs/wire-format.md): protobuf-style keys
// `ordinal * 8 + wireType`, two's-complement varints, little-endian I64 and I32.
namespace nw::wire {

enum class WireType : uint8_t {
  Varint = 0,
  I64 = 1,
  Len = 2,
  I32 = 5,
};

constexpr uint32_t kMaxOrdinal = 536870911;
constexpr size_t kMaxVarintBytes = 10;

class Writer {
 public:
  void key(uint32_t ordinal, WireType type);
  // Negative values are written as their 64-bit two's complement, 10 bytes long.
  void varint(uint64_t value);
  void fixed64(uint64_t value);
  void lengthDelimited(ByteView body);
  void raw(ByteView bytes);

  const Bytes& bytes() const { return bytes_; }
  Bytes take() { return std::move(bytes_); }

 private:
  Bytes bytes_;
};

struct Field {
  uint32_t ordinal = 0;
  WireType type = WireType::Varint;
  // Varint value, or the raw I64 / I32 bits.
  uint64_t number = 0;
  // LEN body.
  ByteView body;
  // The key and body exactly as they appear in the input.
  ByteView raw;
};

class Reader {
 public:
  explicit Reader(ByteView bytes) : bytes_(bytes) {}

  bool atEnd() const { return position_ == bytes_.size(); }
  // Malformed on a truncated field, an over-long varint, ordinal 0 or above kMaxOrdinal,
  // or a wire type the format never emits (groups, 6, 7).
  Status next(Field& field);
  Status readVarint(uint64_t& value);

 private:
  Status readBody(Field& field);
  Status readFixed(size_t width, uint64_t& value);

  ByteView bytes_;
  size_t position_ = 0;
};

Bytes varintBytes(uint64_t value);
// All values of a packed LEN body; false on a malformed body.
bool readPackedVarints(ByteView body, std::vector<uint64_t>& values);
bool readPackedFixed64(ByteView body, std::vector<uint64_t>& values);

}  // namespace nw::wire
