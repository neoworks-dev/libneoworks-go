#include "wire.hpp"

#include <utility>

namespace nw::wire {

void Writer::key(uint32_t ordinal, WireType type) {
  varint(uint64_t{ordinal} * 8 + static_cast<uint64_t>(type));
}

void Writer::varint(uint64_t value) {
  while (value > 0x7f) {
    bytes_.push_back(static_cast<uint8_t>((value & 0x7f) | 0x80));
    value >>= 7;
  }
  bytes_.push_back(static_cast<uint8_t>(value));
}

void Writer::fixed64(uint64_t value) {
  for (int index = 0; index < 8; ++index) {
    bytes_.push_back(static_cast<uint8_t>(value >> (8 * index)));
  }
}

void Writer::lengthDelimited(ByteView body) {
  varint(body.size());
  raw(body);
}

void Writer::raw(ByteView bytes) { bytes_.insert(bytes_.end(), bytes.begin(), bytes.end()); }

Status Reader::readVarint(uint64_t& value) {
  value = 0;
  for (size_t index = 0; index < kMaxVarintBytes; ++index) {
    if (position_ == bytes_.size()) {
      return Status::Malformed;
    }
    uint8_t byte = bytes_[position_++];
    bool overflows = index == kMaxVarintBytes - 1 && byte > 1;
    if (overflows) {
      return Status::Malformed;
    }
    value |= uint64_t{byte & 0x7fu} << (7 * index);
    if ((byte & 0x80) == 0) {
      return Status::Ok;
    }
  }
  return Status::Malformed;
}

Status Reader::readFixed(size_t width, uint64_t& value) {
  if (bytes_.size() - position_ < width) {
    return Status::Malformed;
  }
  value = 0;
  for (size_t index = 0; index < width; ++index) {
    value |= uint64_t{bytes_[position_ + index]} << (8 * index);
  }
  position_ += width;
  return Status::Ok;
}

Status Reader::readBody(Field& field) {
  switch (field.type) {
    case WireType::Varint:
      return readVarint(field.number);
    case WireType::I64:
      return readFixed(8, field.number);
    case WireType::I32:
      return readFixed(4, field.number);
    case WireType::Len:
      break;
  }
  uint64_t length = 0;
  Status status = readVarint(length);
  if (status != Status::Ok || length > bytes_.size() - position_) {
    return Status::Malformed;
  }
  size_t bodyLength = static_cast<size_t>(length);
  field.body = bytes_.subspan(position_, bodyLength);
  position_ += bodyLength;
  return Status::Ok;
}

Status Reader::next(Field& field) {
  size_t start = position_;
  uint64_t key = 0;
  if (readVarint(key) != Status::Ok) {
    return Status::Malformed;
  }
  uint64_t ordinal = key / 8;
  uint64_t type = key % 8;
  bool knownType = type == 0 || type == 1 || type == 2 || type == 5;
  if (ordinal == 0 || ordinal > kMaxOrdinal || !knownType) {
    return Status::Malformed;
  }
  field = Field{};
  field.ordinal = static_cast<uint32_t>(ordinal);
  field.type = static_cast<WireType>(type);
  if (readBody(field) != Status::Ok) {
    return Status::Malformed;
  }
  field.raw = bytes_.subspan(start, position_ - start);
  return Status::Ok;
}

Bytes varintBytes(uint64_t value) {
  Writer writer;
  writer.varint(value);
  return writer.take();
}

bool readPackedVarints(ByteView body, std::vector<uint64_t>& values) {
  Reader reader(body);
  while (!reader.atEnd()) {
    uint64_t value = 0;
    if (reader.readVarint(value) != Status::Ok) {
      return false;
    }
    values.push_back(value);
  }
  return true;
}

bool readPackedFixed64(ByteView body, std::vector<uint64_t>& values) {
  if (body.size() % 8 != 0) {
    return false;
  }
  for (size_t offset = 0; offset < body.size(); offset += 8) {
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
      value |= uint64_t{body[offset + index]} << (8 * index);
    }
    values.push_back(value);
  }
  return true;
}

}  // namespace nw::wire
