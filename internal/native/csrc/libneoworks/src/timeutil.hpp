#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nw {

// Strict RFC 3339 UTC: YYYY-MM-DDTHH:MM:SS[.fraction]Z. Returns Unix seconds.
std::optional<int64_t> parseRfc3339Utc(std::string_view text);
// Lenient instant for calendar data: date-only (UTC midnight), Z, or a +-HH:MM offset.
std::optional<int64_t> parseInstant(std::string_view text);
std::string formatRfc3339Utc(int64_t unixSeconds);
int64_t currentUnixSeconds();

}  // namespace nw
