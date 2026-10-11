#include "schema_values.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <system_error>
#include <vector>

namespace nw {

static_assert(sizeof(wchar_t) == 4, "patterns are matched over UTF-32 code points");

namespace {

constexpr int64_t kMillisPerDay = 86400000;
constexpr int64_t kNanosPerSecond = 1000000000;
constexpr int64_t kNanosPerDay = 86400 * kNanosPerSecond;
// Epoch days of 0000-01-01 and 9999-12-31, the four-digit-year window.
constexpr int64_t kMinFourDigitDay = -719528;
constexpr int64_t kMaxFourDigitDay = 2932896;
constexpr int64_t kMinFourDigitMillis = kMinFourDigitDay * kMillisPerDay;
constexpr int64_t kMaxFourDigitMillis = (kMaxFourDigitDay + 1) * kMillisPerDay - 1;

bool isDigit(char character) { return character >= '0' && character <= '9'; }

bool allDigits(std::string_view text) {
  return !text.empty() && std::all_of(text.begin(), text.end(), isDigit);
}

int digitsValue(std::string_view text) {
  int value = 0;
  for (char character : text) {
    value = value * 10 + (character - '0');
  }
  return value;
}

// -1 unless both characters at `index` are digits.
int twoDigits(std::string_view text, size_t index) {
  if (index + 2 > text.size() || !allDigits(text.substr(index, 2))) {
    return -1;
  }
  return digitsValue(text.substr(index, 2));
}

int64_t floorDivide(int64_t numerator, int64_t denominator) {
  int64_t quotient = numerator / denominator;
  if ((numerator % denominator != 0) && ((numerator < 0) != (denominator < 0))) {
    quotient -= 1;
  }
  return quotient;
}

bool isLeapYear(int64_t year) { return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0); }

int daysInMonth(int64_t year, int month) {
  if (month == 2 && isLeapYear(year)) {
    return 29;
  }
  if (month == 2) {
    return 28;
  }
  if (month == 4 || month == 6 || month == 9 || month == 11) {
    return 30;
  }
  return 31;
}

// Howard Hinnant's days_from_civil.
int64_t daysFromCivil(int64_t year, int64_t month, int64_t day) {
  int64_t shiftedYear = year;
  if (month <= 2) {
    shiftedYear -= 1;
  }
  int64_t era = floorDivide(shiftedYear, 400);
  int64_t yearOfEra = shiftedYear - era * 400;
  int64_t monthIndex = month + 9;
  if (month > 2) {
    monthIndex = month - 3;
  }
  int64_t dayOfYear = (153 * monthIndex + 2) / 5 + day - 1;
  int64_t dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
  return era * 146097 + dayOfEra - 719468;
}

struct CivilDate {
  int64_t year;
  int64_t month;
  int64_t day;
};

CivilDate civilFromDays(int64_t days) {
  int64_t shifted = days + 719468;
  int64_t era = floorDivide(shifted, 146097);
  int64_t dayOfEra = shifted - era * 146097;
  int64_t yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
  int64_t dayOfYear = dayOfEra - (yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100);
  int64_t monthIndex = (5 * dayOfYear + 2) / 153;
  int64_t day = dayOfYear - (153 * monthIndex + 2) / 5 + 1;
  int64_t month = monthIndex - 9;
  if (monthIndex < 10) {
    month = monthIndex + 3;
  }
  int64_t year = yearOfEra + era * 400;
  if (month <= 2) {
    year += 1;
  }
  return CivilDate{year, month, day};
}

std::string padded(int64_t value, size_t width) {
  std::string text = std::to_string(value);
  if (text.size() < width) {
    text.insert(0, width - text.size(), '0');
  }
  return text;
}

std::string_view trimAsciiSpace(std::string_view text) {
  auto isSpace = [](char character) { return character == ' ' || (character >= '\t' && character <= '\r'); };
  while (!text.empty() && isSpace(text.front())) {
    text.remove_prefix(1);
  }
  while (!text.empty() && isSpace(text.back())) {
    text.remove_suffix(1);
  }
  return text;
}

struct DecimalParts {
  bool negative = false;
  std::string_view integer;
  std::string_view fraction;
};

// [+-]?[0-9]+(\.[0-9]*)?
std::optional<DecimalParts> splitDecimal(std::string_view text) {
  DecimalParts parts;
  if (!text.empty() && (text.front() == '+' || text.front() == '-')) {
    parts.negative = text.front() == '-';
    text.remove_prefix(1);
  }
  size_t point = text.find('.');
  parts.integer = text.substr(0, point);
  if (point != std::string_view::npos) {
    parts.fraction = text.substr(point + 1);
  }
  bool digitsOnly = allDigits(parts.integer) && std::all_of(parts.fraction.begin(), parts.fraction.end(), isDigit);
  if (!digitsOnly) {
    return std::nullopt;
  }
  return parts;
}

// Seconds of the day for "HH:MM:SS" at `index`, or -1.
int64_t parseClock(std::string_view text, size_t index) {
  if (index + 8 > text.size() || text[index + 2] != ':' || text[index + 5] != ':') {
    return -1;
  }
  int hours = twoDigits(text, index);
  int minutes = twoDigits(text, index + 3);
  int seconds = twoDigits(text, index + 6);
  if (hours < 0 || minutes < 0 || seconds < 0 || hours > 23 || minutes > 59 || seconds > 59) {
    return -1;
  }
  return int64_t{hours} * 3600 + int64_t{minutes} * 60 + seconds;
}

// The fraction after a '.', as nanoseconds; `length` receives the digits consumed.
std::optional<int64_t> parseFraction(std::string_view text, size_t& length) {
  length = 0;
  while (length < text.size() && isDigit(text[length])) {
    ++length;
  }
  if (length == 0) {
    return std::nullopt;
  }
  std::string digits(text.substr(0, std::min<size_t>(length, 9)));
  digits.resize(9, '0');
  return int64_t{std::stoll(digits)};
}

// Offset in minutes for "Z", "z" or "+HH:MM" / "-HH:MM" filling the whole text.
std::optional<int64_t> parseOffset(std::string_view text) {
  if (text == "Z" || text == "z") {
    return int64_t{0};
  }
  if (text.size() != 6 || (text[0] != '+' && text[0] != '-') || text[3] != ':') {
    return std::nullopt;
  }
  int hours = twoDigits(text, 1);
  int minutes = twoDigits(text, 4);
  if (hours < 0 || minutes < 0 || hours > 23 || minutes > 59) {
    return std::nullopt;
  }
  int64_t offset = int64_t{hours} * 60 + minutes;
  if (text[0] == '-') {
    return -offset;
  }
  return offset;
}

struct TimeOfDay {
  int64_t nanos = 0;
  std::string_view rest;
};

// "HH:MM:SS[.fraction]" followed by anything.
std::optional<TimeOfDay> parseTimeOfDay(std::string_view text) {
  int64_t seconds = parseClock(text, 0);
  if (seconds < 0) {
    return std::nullopt;
  }
  TimeOfDay time{seconds * kNanosPerSecond, text.substr(8)};
  if (time.rest.empty() || time.rest.front() != '.') {
    return time;
  }
  size_t length = 0;
  std::optional<int64_t> fraction = parseFraction(time.rest.substr(1), length);
  if (!fraction.has_value()) {
    return std::nullopt;
  }
  time.nanos += *fraction;
  time.rest = time.rest.substr(1 + length);
  return time;
}

std::u16string utf8ToUtf16(std::string_view text) {
  std::optional<std::wstring> wide = utf8ToWide(text);
  std::u16string units;
  if (!wide.has_value()) {
    return units;
  }
  for (wchar_t codePoint : *wide) {
    uint32_t value = static_cast<uint32_t>(codePoint);
    if (value < 0x10000) {
      units.push_back(static_cast<char16_t>(value));
      continue;
    }
    value -= 0x10000;
    units.push_back(static_cast<char16_t>(0xd800 + (value >> 10)));
    units.push_back(static_cast<char16_t>(0xdc00 + (value & 0x3ff)));
  }
  return units;
}

std::string canonicalObjectText(const Json& value) {
  std::vector<std::pair<std::u16string, std::string>> keys;
  for (const auto& entry : value.items()) {
    keys.emplace_back(utf8ToUtf16(entry.key()), entry.key());
  }
  std::sort(keys.begin(), keys.end());
  std::string text = "{";
  for (const auto& [sortKey, key] : keys) {
    if (text.size() > 1) {
      text += ",";
    }
    text += Json(key).dump() + ":" + canonicalJsonText(value.at(key));
  }
  return text + "}";
}

std::string exponentForm(const std::string& digits, int64_t exponent) {
  std::string text(1, digits[0]);
  if (digits.size() > 1) {
    text += "." + digits.substr(1);
  }
  text += "e";
  if (exponent >= 0) {
    text += "+";
  }
  return text + std::to_string(exponent);
}


// Decodes the code point starting at `index`; 0 on invalid UTF-8, else the bytes consumed.
size_t decodeCodePoint(std::string_view text, size_t index, uint32_t& codePoint) {
  uint8_t lead = static_cast<uint8_t>(text[index]);
  struct Lead {
    uint8_t mask;
    uint8_t pattern;
    size_t length;
    uint32_t minimum;
  };
  static const Lead leads[] = {{0x80, 0x00, 1, 0}, {0xe0, 0xc0, 2, 0x80}, {0xf0, 0xe0, 3, 0x800}, {0xf8, 0xf0, 4, 0x10000}};
  const Lead* matched = std::find_if(std::begin(leads), std::end(leads),
                                     [&](const Lead& candidate) { return (lead & candidate.mask) == candidate.pattern; });
  if (matched == std::end(leads) || index + matched->length > text.size()) {
    return 0;
  }
  codePoint = lead & static_cast<uint8_t>(~matched->mask);
  for (size_t offset = 1; offset < matched->length; ++offset) {
    uint8_t continuation = static_cast<uint8_t>(text[index + offset]);
    if ((continuation & 0xc0) != 0x80) {
      return 0;
    }
    codePoint = (codePoint << 6) | (continuation & 0x3fu);
  }
  bool surrogate = codePoint >= 0xd800 && codePoint <= 0xdfff;
  if (codePoint < matched->minimum || codePoint > 0x10ffff || surrogate) {
    return 0;
  }
  return matched->length;
}

}  // namespace

std::optional<std::wstring> utf8ToWide(std::string_view text) {
  std::wstring wide;
  size_t index = 0;
  while (index < text.size()) {
    uint32_t codePoint = 0;
    size_t length = decodeCodePoint(text, index, codePoint);
    if (length == 0) {
      return std::nullopt;
    }
    wide.push_back(static_cast<wchar_t>(codePoint));
    index += length;
  }
  return wide;
}

std::optional<size_t> countCodePoints(std::string_view text) {
  std::optional<std::wstring> wide = utf8ToWide(text);
  if (!wide.has_value()) {
    return std::nullopt;
  }
  return wide->size();
}

std::optional<int64_t> parseSignedDecimalText(std::string_view text) {
  std::string_view magnitude = text;
  if (!magnitude.empty() && magnitude.front() == '-') {
    magnitude.remove_prefix(1);
  }
  bool canonical = allDigits(magnitude) && (magnitude == "0" || magnitude.front() != '0');
  if (!canonical || text == "-0") {
    return std::nullopt;
  }
  int64_t value = 0;
  auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc() || end != text.data() + text.size()) {
    return std::nullopt;
  }
  return value;
}

std::optional<uint64_t> parseUnsignedDecimalText(std::string_view text) {
  bool canonical = allDigits(text) && (text == "0" || text.front() != '0');
  if (!canonical) {
    return std::nullopt;
  }
  uint64_t value = 0;
  auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc() || end != text.data() + text.size()) {
    return std::nullopt;
  }
  return value;
}

std::optional<std::string> canonicalDecimal(std::string_view text, uint32_t precision, uint32_t scale) {
  std::optional<DecimalParts> parts = splitDecimal(trimAsciiSpace(text));
  if (!parts.has_value() || parts->fraction.size() > scale) {
    return std::nullopt;
  }
  std::string integerPart(parts->integer);
  integerPart.erase(0, std::min(integerPart.find_first_not_of('0'), integerPart.size() - 1));
  std::string fraction(parts->fraction);
  fraction.resize(scale, '0');
  size_t significantFraction = fraction.find_last_not_of('0') + 1;
  size_t digits = integerPart.size() + scale;
  if (integerPart == "0") {
    digits = significantFraction;
  }
  if (digits > precision) {
    return std::nullopt;
  }
  std::string magnitude = integerPart;
  if (scale > 0) {
    magnitude += "." + fraction;
  }
  bool isZero = integerPart == "0" && significantFraction == 0;
  if (parts->negative && !isZero) {
    return "-" + magnitude;
  }
  return magnitude;
}

std::optional<int64_t> dateToDays(std::string_view text) {
  if (text.size() != 10 || text[4] != '-' || text[7] != '-' || !allDigits(text.substr(0, 4))) {
    return std::nullopt;
  }
  int64_t year = digitsValue(text.substr(0, 4));
  int month = twoDigits(text, 5);
  int day = twoDigits(text, 8);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) {
    return std::nullopt;
  }
  return daysFromCivil(year, month, day);
}

std::optional<std::string> daysToDate(int64_t days) {
  if (days < kMinFourDigitDay || days > kMaxFourDigitDay) {
    return std::nullopt;
  }
  CivilDate date = civilFromDays(days);
  return padded(date.year, 4) + "-" + padded(date.month, 2) + "-" + padded(date.day, 2);
}

std::optional<int64_t> timeToNanos(std::string_view text) {
  std::optional<TimeOfDay> time = parseTimeOfDay(text);
  if (!time.has_value() || !time->rest.empty()) {
    return std::nullopt;
  }
  return time->nanos;
}

std::optional<std::string> nanosToTime(int64_t nanos) {
  if (nanos < 0 || nanos >= kNanosPerDay) {
    return std::nullopt;
  }
  int64_t totalSeconds = nanos / kNanosPerSecond;
  int64_t fraction = nanos % kNanosPerSecond;
  std::string text = padded(totalSeconds / 3600, 2) + ":" + padded(totalSeconds % 3600 / 60, 2) + ":" +
                     padded(totalSeconds % 60, 2);
  if (fraction == 0) {
    return text;
  }
  return text + "." + padded(fraction, 9);
}

std::optional<int64_t> timestampToMillis(std::string_view text) {
  if (text.size() < 20 || (text[10] != 'T' && text[10] != 't')) {
    return std::nullopt;
  }
  std::optional<int64_t> days = dateToDays(text.substr(0, 10));
  std::optional<TimeOfDay> time = parseTimeOfDay(text.substr(11));
  if (!days.has_value() || !time.has_value()) {
    return std::nullopt;
  }
  std::optional<int64_t> offsetMinutes = parseOffset(time->rest);
  if (!offsetMinutes.has_value()) {
    return std::nullopt;
  }
  int64_t millis = *days * kMillisPerDay + time->nanos / 1000000 - *offsetMinutes * 60000;
  if (millis < kMinFourDigitMillis || millis > kMaxFourDigitMillis) {
    return std::nullopt;
  }
  return millis;
}

std::optional<std::string> millisToTimestamp(int64_t millis) {
  if (millis < kMinFourDigitMillis || millis > kMaxFourDigitMillis) {
    return std::nullopt;
  }
  int64_t days = floorDivide(millis, kMillisPerDay);
  int64_t millisOfDay = millis - days * kMillisPerDay;
  int64_t secondOfDay = millisOfDay / 1000;
  std::optional<std::string> date = daysToDate(days);
  return *date + "T" + padded(secondOfDay / 3600, 2) + ":" + padded(secondOfDay % 3600 / 60, 2) + ":" +
         padded(secondOfDay % 60, 2) + "." + padded(millisOfDay % 1000, 3) + "Z";
}

std::optional<Bytes> uuidTextToBytes(std::string_view text) {
  if (text.size() != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-') {
    return std::nullopt;
  }
  std::string hex;
  for (char character : text) {
    if (character != '-') {
      hex.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }
  }
  std::optional<Bytes> bytes = fromHex(hex);
  if (!bytes.has_value() || bytes->size() != 16) {
    return std::nullopt;
  }
  return bytes;
}

std::optional<std::string> uuidBytesToText(ByteView bytes) {
  if (bytes.size() != 16) {
    return std::nullopt;
  }
  std::string hex = toHex(bytes);
  return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" +
         hex.substr(20);
}

std::string canonicalJsonText(const Json& value) {
  if (value.is_object()) {
    return canonicalObjectText(value);
  }
  if (value.is_number()) {
    return formatJsNumber(value.get<double>());
  }
  if (!value.is_array()) {
    return value.dump();
  }
  std::string text = "[";
  for (const Json& element : value) {
    if (text.size() > 1) {
      text += ",";
    }
    text += canonicalJsonText(element);
  }
  return text + "]";
}

std::string formatJsNumber(double value) {
  if (value == 0) {
    return "0";
  }
  if (value < 0) {
    return "-" + formatJsNumber(-value);
  }
  char buffer[64];
  auto [end, error] = std::to_chars(buffer, buffer + sizeof(buffer), value, std::chars_format::scientific);
  std::string scientific(buffer, end);
  size_t exponentAt = scientific.find('e');
  std::string digits = scientific.substr(0, exponentAt);
  digits.erase(std::remove(digits.begin(), digits.end(), '.'), digits.end());
  int64_t exponent = std::stoll(scientific.substr(exponentAt + 1));
  int64_t count = static_cast<int64_t>(digits.size());
  int64_t pointAt = exponent + 1;
  if (count <= pointAt && pointAt <= 21) {
    return digits + std::string(static_cast<size_t>(pointAt - count), '0');
  }
  if (0 < pointAt && pointAt <= 21) {
    return digits.substr(0, static_cast<size_t>(pointAt)) + "." + digits.substr(static_cast<size_t>(pointAt));
  }
  if (-6 < pointAt && pointAt <= 0) {
    return "0." + std::string(static_cast<size_t>(-pointAt), '0') + digits;
  }
  return exponentForm(digits, exponent);
}

bool isRfc3339Time(std::string_view text) {
  std::optional<TimeOfDay> time = parseTimeOfDay(text);
  return time.has_value() && parseOffset(time->rest).has_value();
}

}  // namespace nw
