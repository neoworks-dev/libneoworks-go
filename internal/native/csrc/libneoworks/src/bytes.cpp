#include "bytes.hpp"

#include <sodium.h>

#include <cstdlib>
#include <cstring>
#include <new>

namespace nw {

SecretBytes::SecretBytes(size_t size) {
  if (size == 0) {
    return;
  }
  data_ = static_cast<uint8_t*>(sodium_malloc(size));
  if (data_ == nullptr) {
    throw std::bad_alloc();
  }
  size_ = size;
  sodium_memzero(data_, size_);
}

SecretBytes::SecretBytes(ByteView source) : SecretBytes(source.size()) {
  if (source.empty() || source.data() == nullptr || data_ == nullptr) {
    return;
  }
  std::memcpy(data_, source.data(), source.size());
}

SecretBytes::SecretBytes(SecretBytes&& other) noexcept : data_(other.data_), size_(other.size_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  release();
  data_ = other.data_;
  size_ = other.size_;
  other.data_ = nullptr;
  other.size_ = 0;
  return *this;
}

SecretBytes::~SecretBytes() { release(); }

void SecretBytes::release() {
  if (data_ != nullptr) {
    sodium_free(data_);
  }
  data_ = nullptr;
  size_ = 0;
}

bool SecretBytes::constantTimeEquals(ByteView other) const {
  if (other.size() != size_) {
    return false;
  }
  if (size_ == 0) {
    return true;
  }
  return sodium_memcmp(data_, other.data(), size_) == 0;
}

ByteView viewOf(std::string_view text) {
  return ByteView(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

ByteView viewOf(const Bytes& bytes) { return ByteView(bytes.data(), bytes.size()); }

Bytes bytesOf(std::string_view text) {
  ByteView view = viewOf(text);
  return Bytes(view.begin(), view.end());
}

void appendTo(Bytes& destination, ByteView source) {
  destination.insert(destination.end(), source.begin(), source.end());
}

Bytes concat(ByteView first, ByteView second) {
  Bytes joined;
  joined.reserve(first.size() + second.size());
  appendTo(joined, first);
  appendTo(joined, second);
  return joined;
}

std::string toBase64Url(ByteView bytes) {
  size_t encodedCapacity = sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  std::string encoded(encodedCapacity, '\0');
  sodium_bin2base64(encoded.data(), encodedCapacity, bytes.data(), bytes.size(),
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  encoded.resize(encodedCapacity - 1);
  return encoded;
}

std::optional<Bytes> fromBase64Url(std::string_view text) {
  Bytes decoded(text.size() / 4 * 3 + 3);
  size_t decodedLength = 0;
  const char* parseEnd = nullptr;
  int status = sodium_base642bin(decoded.data(), decoded.size(), text.data(), text.size(), nullptr,
                                 &decodedLength, &parseEnd, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  if (status != 0) {
    return std::nullopt;
  }
  if (parseEnd != text.data() + text.size()) {
    return std::nullopt;
  }
  decoded.resize(decodedLength);
  return decoded;
}

std::string toHex(ByteView bytes) {
  std::string hex(bytes.size() * 2 + 1, '\0');
  sodium_bin2hex(hex.data(), hex.size(), bytes.data(), bytes.size());
  hex.resize(bytes.size() * 2);
  return hex;
}

std::optional<Bytes> fromHex(std::string_view text) {
  Bytes decoded(text.size() / 2 + 1);
  size_t decodedLength = 0;
  const char* parseEnd = nullptr;
  int status = sodium_hex2bin(decoded.data(), decoded.size(), text.data(), text.size(), nullptr,
                              &decodedLength, &parseEnd);
  if (status != 0 || parseEnd != text.data() + text.size()) {
    return std::nullopt;
  }
  decoded.resize(decodedLength);
  return decoded;
}

namespace {

bool isValidUuidCharacter(size_t index, char character) {
  bool isDashPosition = index == 8 || index == 13 || index == 18 || index == 23;
  if (isDashPosition) {
    return character == '-';
  }
  bool isDigit = character >= '0' && character <= '9';
  bool isLowerHex = character >= 'a' && character <= 'f';
  return isDigit || isLowerHex;
}

}  // namespace

bool isLowercaseUuid(std::string_view text) {
  if (text.size() != 36) {
    return false;
  }
  for (size_t index = 0; index < text.size(); ++index) {
    if (!isValidUuidCharacter(index, text[index])) {
      return false;
    }
  }
  return true;
}

}  // namespace nw
