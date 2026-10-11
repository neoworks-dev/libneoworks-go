#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nw {

using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;

// Fixed-size secret held in sodium_malloc memory: locked, guard-paged, zeroed on free.
class SecretBytes {
 public:
  SecretBytes() = default;
  explicit SecretBytes(size_t size);
  explicit SecretBytes(ByteView source);
  SecretBytes(SecretBytes&& other) noexcept;
  SecretBytes& operator=(SecretBytes&& other) noexcept;
  SecretBytes(const SecretBytes&) = delete;
  SecretBytes& operator=(const SecretBytes&) = delete;
  ~SecretBytes();

  uint8_t* data() { return data_; }
  const uint8_t* data() const { return data_; }
  size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }
  ByteView view() const { return ByteView(data_, size_); }
  bool constantTimeEquals(ByteView other) const;

 private:
  void release();

  uint8_t* data_ = nullptr;
  size_t size_ = 0;
};

ByteView viewOf(std::string_view text);
ByteView viewOf(const Bytes& bytes);
Bytes bytesOf(std::string_view text);
Bytes concat(ByteView first, ByteView second);
void appendTo(Bytes& destination, ByteView source);

std::string toBase64Url(ByteView bytes);
std::optional<Bytes> fromBase64Url(std::string_view text);
std::string toHex(ByteView bytes);
std::optional<Bytes> fromHex(std::string_view text);

bool isLowercaseUuid(std::string_view text);

}  // namespace nw
