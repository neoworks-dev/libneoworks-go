#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "bytes.hpp"

namespace nw {

// tlv(ctx, f...) = utf8(ctx) || 0x00 || for each field: u32be(len) || bytes.
class TlvWriter {
 public:
  explicit TlvWriter(std::string_view context);

  TlvWriter& text(std::string_view value);
  TlvWriter& optionalText(const std::optional<std::string>& value);
  TlvWriter& bytes(ByteView value);
  TlvWriter& u8(uint8_t value);
  TlvWriter& flag(bool value);
  TlvWriter& u32(uint32_t value);
  TlvWriter& u64(uint64_t value);
  TlvWriter& absent();

  Bytes finish();

 private:
  void appendField(ByteView value);

  Bytes buffer_;
};

// Big-endian integers from a field of exactly the right width.
std::optional<uint32_t> decodeU32(ByteView field);
std::optional<uint64_t> decodeU64(ByteView field);

class TlvReader {
 public:
  explicit TlvReader(ByteView encoded);

  // False when the context terminator is missing; the reader is then unusable.
  bool valid() const { return valid_; }
  std::string_view context() const { return context_; }
  std::optional<ByteView> nextField();
  bool atEnd() const { return position_ == encoded_.size(); }
  bool malformed() const { return malformed_; }

 private:
  ByteView encoded_;
  std::string_view context_;
  size_t position_ = 0;
  bool valid_ = false;
  bool malformed_ = false;
};

}  // namespace nw
