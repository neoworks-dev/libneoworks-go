#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "bytes.hpp"
#include "json.hpp"

// Conversions between the JSON mapping (contract amendment 7) and wire values. Each
// mirrors the openschema codec runtime (src/emit/codec/runtimePrelude.ts) so the core
// and generated TypeScript codecs agree byte for byte.
namespace nw {

std::optional<std::wstring> utf8ToWide(std::string_view text);
// Code points in valid UTF-8, nullopt for invalid UTF-8.
std::optional<size_t> countCodePoints(std::string_view text);

// "-?(0|[1-9][0-9]*)" in range; "-0" is rejected.
std::optional<int64_t> parseSignedDecimalText(std::string_view text);
std::optional<uint64_t> parseUnsignedDecimalText(std::string_view text);

// Canonical decimal: optional '-', no leading zeros, exactly `scale` fraction digits,
// -0 normalised to 0. Accepts surrounding whitespace and a leading '+' like the TS runtime.
std::optional<std::string> canonicalDecimal(std::string_view text, uint32_t precision, uint32_t scale);

// Days since 1970-01-01 for "YYYY-MM-DD", years 0000..9999.
std::optional<int64_t> dateToDays(std::string_view text);
std::optional<std::string> daysToDate(int64_t days);
// Nanoseconds since midnight for "HH:MM:SS" with an optional 1..9 digit fraction.
std::optional<int64_t> timeToNanos(std::string_view text);
std::optional<std::string> nanosToTime(int64_t nanos);
// Epoch milliseconds for an RFC 3339 date-time with Z or a numeric offset; fraction
// digits beyond milliseconds are truncated.
std::optional<int64_t> timestampToMillis(std::string_view text);
// "YYYY-MM-DDTHH:MM:SS.sssZ".
std::optional<std::string> millisToTimestamp(int64_t millis);

// 8-4-4-4-12 hex in either case.
std::optional<Bytes> uuidTextToBytes(std::string_view text);
std::optional<std::string> uuidBytesToText(ByteView bytes);

// JSON.stringify of the value with object keys sorted in UTF-16 code-unit order, as
// the TS runtime's canonicalJson produces it.
std::string canonicalJsonText(const Json& value);
// ECMAScript Number::toString for a finite double.
std::string formatJsNumber(double value);

// RFC 3339 full-time: "HH:MM:SS[.fraction]" with "Z" or a numeric offset.
bool isRfc3339Time(std::string_view text);

// False only for a format this runtime knows and the value does not satisfy.
bool matchesFormat(std::string_view format, std::string_view value);

}  // namespace nw
