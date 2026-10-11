#include "contact_code.hpp"

#include <cctype>
#include <cstring>

namespace nw {

namespace {

constexpr char kAlphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
constexpr size_t kCodeLength = 12;

char canonicalCharacter(char raw) {
  char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(raw)));
  if (upper == 'O') {
    return '0';
  }
  if (upper == 'I' || upper == 'L') {
    return '1';
  }
  return upper;
}

int alphabetValue(char character) {
  const char* position = std::strchr(kAlphabet, character);
  if (character == '\0' || position == nullptr) {
    return -1;
  }
  return static_cast<int>(position - kAlphabet);
}

}  // namespace

Result<std::string> normalizeContactCode(std::string_view input) {
  std::string canonical;
  for (char raw : input) {
    if (raw == '-' || raw == ' ') {
      continue;
    }
    canonical += canonicalCharacter(raw);
  }
  if (canonical.size() != kCodeLength) {
    return Status::Malformed;
  }
  int sum = 0;
  for (size_t position = 0; position < kCodeLength; ++position) {
    int value = alphabetValue(canonical[position]);
    if (value < 0) {
      return Status::Malformed;
    }
    if (position < kCodeLength - 1) {
      sum += value * static_cast<int>(2 * position + 1);
    }
  }
  if (alphabetValue(canonical.back()) != sum % 32) {
    return Status::Malformed;
  }
  return canonical;
}

}  // namespace nw
