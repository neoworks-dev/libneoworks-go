#pragma once

#include <string>
#include <string_view>

#include "status.hpp"

namespace nw {

// Contact codes are 12 Crockford base32 characters: 11 random ones and a check character, the sum
// of value * (2 * position + 1) over the first 11 modulo 32. Any single mistyped character fails.
// Strips spaces and hyphens, uppercases and maps O, I and L to 0, 1 and 1. Returns the canonical
// code without separators. Malformed: wrong length, character outside the alphabet or bad check.
Result<std::string> normalizeContactCode(std::string_view input);

}  // namespace nw
