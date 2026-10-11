#include "tlv.hpp"

namespace nw {

namespace {

void appendBigEndian(Bytes& destination, uint64_t value, int byteCount) {
  for (int shift = (byteCount - 1) * 8; shift >= 0; shift -= 8) {
    destination.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
  }
}

}  // namespace

TlvWriter::TlvWriter(std::string_view context) {
  appendTo(buffer_, viewOf(context));
  buffer_.push_back(0x00);
}

void TlvWriter::appendField(ByteView value) {
  appendBigEndian(buffer_, value.size(), 4);
  appendTo(buffer_, value);
}

TlvWriter& TlvWriter::text(std::string_view value) {
  appendField(viewOf(value));
  return *this;
}

TlvWriter& TlvWriter::optionalText(const std::optional<std::string>& value) {
  if (!value.has_value()) {
    return absent();
  }
  return text(*value);
}

TlvWriter& TlvWriter::bytes(ByteView value) {
  appendField(value);
  return *this;
}

TlvWriter& TlvWriter::u8(uint8_t value) {
  uint8_t encoded[1] = {value};
  appendField(ByteView(encoded, 1));
  return *this;
}

TlvWriter& TlvWriter::flag(bool value) {
  if (value) {
    return u8(1);
  }
  return u8(0);
}

TlvWriter& TlvWriter::u32(uint32_t value) {
  Bytes encoded;
  appendBigEndian(encoded, value, 4);
  appendField(encoded);
  return *this;
}

TlvWriter& TlvWriter::u64(uint64_t value) {
  Bytes encoded;
  appendBigEndian(encoded, value, 8);
  appendField(encoded);
  return *this;
}

TlvWriter& TlvWriter::absent() {
  appendField(ByteView());
  return *this;
}

Bytes TlvWriter::finish() { return std::move(buffer_); }

std::optional<uint32_t> decodeU32(ByteView field) {
  if (field.size() != 4) {
    return std::nullopt;
  }
  uint32_t value = 0;
  for (uint8_t byte : field) {
    value = (value << 8) | byte;
  }
  return value;
}

std::optional<uint64_t> decodeU64(ByteView field) {
  if (field.size() != 8) {
    return std::nullopt;
  }
  uint64_t value = 0;
  for (uint8_t byte : field) {
    value = (value << 8) | byte;
  }
  return value;
}

TlvReader::TlvReader(ByteView encoded) : encoded_(encoded) {
  for (size_t index = 0; index < encoded_.size(); ++index) {
    if (encoded_[index] != 0x00) {
      continue;
    }
    context_ = std::string_view(reinterpret_cast<const char*>(encoded_.data()), index);
    position_ = index + 1;
    valid_ = true;
    return;
  }
}

std::optional<ByteView> TlvReader::nextField() {
  if (!valid_ || malformed_ || atEnd()) {
    return std::nullopt;
  }
  size_t remaining = encoded_.size() - position_;
  if (remaining < 4) {
    malformed_ = true;
    return std::nullopt;
  }
  uint64_t length = 0;
  for (int index = 0; index < 4; ++index) {
    length = (length << 8) | encoded_[position_ + index];
  }
  position_ += 4;
  if (length > encoded_.size() - position_) {
    malformed_ = true;
    return std::nullopt;
  }
  ByteView field = encoded_.subspan(position_, static_cast<size_t>(length));
  position_ += static_cast<size_t>(length);
  return field;
}

}  // namespace nw
