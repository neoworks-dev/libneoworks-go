#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "bytes.hpp"
#include "status.hpp"

namespace nw {

constexpr size_t kBip39WordCount = 2048;
extern const char* const kBip39Words[kBip39WordCount];

constexpr size_t kRecoveryEntropyBytes = 32;
constexpr size_t kRecoveryWordCount = 24;

// The 32 byte recovery entropy as 24 BIP39 English words: 256 bits of entropy plus the first 8
// bits of SHA-256(entropy) as checksum, 11 bits per word.
Result<std::vector<std::string>> recoveryEntropyToWords(ByteView entropy);

// The inverse. Words are matched case-insensitively. Malformed: wrong count or unknown word;
// AuthenticationFailed: the checksum does not match.
Result<Bytes> recoveryWordsToEntropy(const std::vector<std::string>& words);

// Splits on spaces, commas and line breaks, then decodes.
Result<Bytes> parseRecoveryWords(std::string_view text);

}  // namespace nw
