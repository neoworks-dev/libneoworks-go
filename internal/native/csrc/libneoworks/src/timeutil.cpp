#include "timeutil.hpp"

#include <array>
#include <chrono>
#include <cstdio>

namespace nw {

namespace {

// Howard Hinnant's days_from_civil / civil_from_days.
int64_t floorDivide(int64_t value, int64_t divisor) {
  int64_t quotient = value / divisor;
  if (value % divisor < 0) {
    quotient -= 1;
  }
  return quotient;
}

unsigned monthFromMarch(unsigned month) {
  if (month > 2) {
    return month - 3;
  }
  return month + 9;
}

int64_t daysFromCivil(int64_t year, unsigned month, unsigned day) {
  if (month <= 2) {
    year -= 1;
  }
  int64_t era = floorDivide(year, 400);
  unsigned yearOfEra = static_cast<unsigned>(year - era * 400);
  unsigned dayOfYear = (153 * monthFromMarch(month) + 2) / 5 + day - 1;
  unsigned dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
  return era * 146097 + static_cast<int64_t>(dayOfEra) - 719468;
}

bool readDigits(std::string_view text, size_t offset, size_t count, int& value) {
  value = 0;
  for (size_t index = 0; index < count; ++index) {
    char character = text[offset + index];
    if (character < '0' || character > '9') {
      return false;
    }
    value = value * 10 + (character - '0');
  }
  return true;
}

bool hasFixedSeparators(std::string_view text) {
  return text[4] == '-' && text[7] == '-' && text[10] == 'T' && text[13] == ':' && text[16] == ':';
}

bool isValidFractionAndZone(std::string_view text) {
  size_t position = 19;
  if (position < text.size() && text[position] == '.') {
    ++position;
    size_t digitStart = position;
    while (position < text.size() && text[position] >= '0' && text[position] <= '9') {
      ++position;
    }
    if (position == digitStart) {
      return false;
    }
  }
  return position + 1 == text.size() && text[position] == 'Z';
}

int daysInMonth(int year, int month) {
  constexpr std::array<int, 12> lengths = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  bool leapYear = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  if (month == 2 && leapYear) {
    return 29;
  }
  return lengths[static_cast<size_t>(month - 1)];
}

}  // namespace

std::optional<int64_t> parseRfc3339Utc(std::string_view text) {
  if (text.size() < 20 || !hasFixedSeparators(text) || !isValidFractionAndZone(text)) {
    return std::nullopt;
  }
  int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  bool digitsValid = readDigits(text, 0, 4, year) && readDigits(text, 5, 2, month) &&
                     readDigits(text, 8, 2, day) && readDigits(text, 11, 2, hour) &&
                     readDigits(text, 14, 2, minute) && readDigits(text, 17, 2, second);
  if (!digitsValid || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) {
    return std::nullopt;
  }
  if (hour > 23 || minute > 59 || second > 59) {
    return std::nullopt;
  }
  int64_t days = daysFromCivil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
  return days * 86400 + static_cast<int64_t>(hour) * 3600 + static_cast<int64_t>(minute) * 60 + second;
}

namespace {

std::optional<int64_t> parseOffsetSeconds(std::string_view offset) {
  if (offset.size() != 6 || (offset[0] != '+' && offset[0] != '-') || offset[3] != ':') {
    return std::nullopt;
  }
  int hours = 0;
  int minutes = 0;
  if (!readDigits(offset, 1, 2, hours) || !readDigits(offset, 4, 2, minutes) || hours > 23 || minutes > 59) {
    return std::nullopt;
  }
  int64_t seconds = hours * 3600 + minutes * 60;
  if (offset[0] == '-') {
    return -seconds;
  }
  return seconds;
}

}  // namespace

std::optional<int64_t> parseInstant(std::string_view text) {
  if (text.size() == 10) {
    return parseRfc3339Utc(std::string(text) + "T00:00:00Z");
  }
  if (text.size() < 25 || text.back() == 'Z') {
    return parseRfc3339Utc(text);
  }
  std::optional<int64_t> offsetSeconds = parseOffsetSeconds(text.substr(text.size() - 6));
  std::string_view local = text.substr(0, text.size() - 6);
  std::optional<int64_t> localSeconds = parseRfc3339Utc(std::string(local) + "Z");
  if (!offsetSeconds || !localSeconds) {
    return std::nullopt;
  }
  return *localSeconds - *offsetSeconds;
}

std::optional<int64_t> parseCanonicalExpiry(std::string_view text) {
  std::optional<int64_t> seconds = parseRfc3339Utc(text);
  if (!seconds.has_value() || formatRfc3339Utc(*seconds) != text) {
    return std::nullopt;
  }
  return seconds;
}

std::string formatRfc3339Utc(int64_t unixSeconds) {
  int64_t days = floorDivide(unixSeconds, 86400);
  int64_t secondsOfDay = unixSeconds - days * 86400;
  int64_t shifted = days + 719468;
  int64_t era = floorDivide(shifted, 146097);
  unsigned dayOfEra = static_cast<unsigned>(shifted - era * 146097);
  unsigned yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
  int64_t year = static_cast<int64_t>(yearOfEra) + era * 400;
  unsigned dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
  unsigned monthPrime = (5 * dayOfYear + 2) / 153;
  unsigned day = dayOfYear - (153 * monthPrime + 2) / 5 + 1;
  unsigned month = monthPrime - 9;
  if (monthPrime < 10) {
    month = monthPrime + 3;
  }
  if (month <= 2) {
    year += 1;
  }
  unsigned hour = static_cast<unsigned>(secondsOfDay / 3600);
  unsigned minute = static_cast<unsigned>(secondsOfDay % 3600 / 60);
  unsigned second = static_cast<unsigned>(secondsOfDay % 60);
  char buffer[64];
  static_cast<void>(std::snprintf(buffer, sizeof(buffer), "%04d-%02u-%02uT%02u:%02u:%02uZ", static_cast<int>(year),
                                  month, day, hour, minute, second));
  return buffer;
}

int64_t currentUnixSeconds() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

}  // namespace nw
