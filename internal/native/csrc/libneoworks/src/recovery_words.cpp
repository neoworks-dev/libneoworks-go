#include "recovery_words.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <map>

namespace nw {

namespace {

constexpr size_t kBitsPerWord = 11;
constexpr size_t kBufferBytes = kRecoveryEntropyBytes + 1;

uint8_t checksumByte(ByteView entropy) {
  uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, entropy.data(), entropy.size());
  return digest[0];
}

unsigned readBits(const Bytes& bytes, size_t start) {
  unsigned value = 0;
  for (size_t offset = 0; offset < kBitsPerWord; ++offset) {
    size_t bit = start + offset;
    value = (value << 1) | ((bytes[bit / 8] >> (7 - bit % 8)) & 1u);
  }
  return value;
}

void writeBits(Bytes& bytes, size_t start, unsigned value) {
  for (size_t offset = 0; offset < kBitsPerWord; ++offset) {
    size_t bit = start + offset;
    unsigned set = (value >> (kBitsPerWord - 1 - offset)) & 1u;
    bytes[bit / 8] = static_cast<uint8_t>(bytes[bit / 8] | (set << (7 - bit % 8)));
  }
}

std::string lowercase(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
  return text;
}

const std::map<std::string, unsigned>& wordIndex() {
  static const std::map<std::string, unsigned> index = [] {
    std::map<std::string, unsigned> built;
    for (unsigned position = 0; position < kBip39WordCount; ++position) {
      built[kBip39Words[position]] = position;
    }
    return built;
  }();
  return index;
}

}  // namespace

Result<std::vector<std::string>> recoveryEntropyToWords(ByteView entropy) {
  if (entropy.size() != kRecoveryEntropyBytes) {
    return Status::InvalidArgument;
  }
  Bytes bits(entropy.begin(), entropy.end());
  bits.push_back(checksumByte(entropy));
  std::vector<std::string> words;
  for (size_t position = 0; position < kRecoveryWordCount; ++position) {
    words.push_back(kBip39Words[readBits(bits, position * kBitsPerWord)]);
  }
  return words;
}

Result<Bytes> recoveryWordsToEntropy(const std::vector<std::string>& words) {
  if (words.size() != kRecoveryWordCount) {
    return Status::Malformed;
  }
  Bytes bits(kBufferBytes, 0);
  for (size_t position = 0; position < words.size(); ++position) {
    auto found = wordIndex().find(lowercase(words[position]));
    if (found == wordIndex().end()) {
      return Status::Malformed;
    }
    writeBits(bits, position * kBitsPerWord, found->second);
  }
  Bytes entropy(bits.begin(), bits.begin() + kRecoveryEntropyBytes);
  if (bits[kRecoveryEntropyBytes] != checksumByte(entropy)) {
    return Status::AuthenticationFailed;
  }
  return entropy;
}

Result<Bytes> parseRecoveryWords(std::string_view text) {
  std::vector<std::string> words;
  std::string current;
  for (char character : text) {
    bool separator = std::isspace(static_cast<unsigned char>(character)) != 0 || character == ',';
    if (!separator) {
      current.push_back(character);
      continue;
    }
    if (!current.empty()) {
      words.push_back(current);
      current.clear();
    }
  }
  if (!current.empty()) {
    words.push_back(current);
  }
  return recoveryWordsToEntropy(words);
}

}  // namespace nw
