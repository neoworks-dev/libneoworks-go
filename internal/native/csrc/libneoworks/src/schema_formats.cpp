#include <algorithm>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "schema_values.hpp"

namespace nw {

namespace {

bool isAsciiSpace(char character) {
  return character == ' ' || (character >= '\t' && character <= '\r');
}

bool isAsciiDigit(char character) { return character >= '0' && character <= '9'; }

bool isAsciiLetter(char character) {
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
}

bool isHexDigit(char character) {
  return isAsciiDigit(character) || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F');
}

bool allOf(std::string_view text, const std::function<bool(char)>& accepted) {
  return std::all_of(text.begin(), text.end(), accepted);
}

std::vector<std::string_view> split(std::string_view text, char separator) {
  std::vector<std::string_view> parts;
  size_t start = 0;
  for (size_t index = 0; index <= text.size(); ++index) {
    if (index == text.size() || text[index] == separator) {
      parts.push_back(text.substr(start, index - start));
      start = index + 1;
    }
  }
  return parts;
}

bool hasNoSpace(std::string_view text) { return std::none_of(text.begin(), text.end(), isAsciiSpace); }

// local@domain, no whitespace, one '@', and a dot inside the domain.
bool isEmail(std::string_view value) {
  size_t at = value.find('@');
  if (at == std::string_view::npos || at == 0 || value.find('@', at + 1) != std::string_view::npos) {
    return false;
  }
  std::string_view domain = value.substr(at + 1);
  size_t dot = domain.find('.', 1);
  bool innerDot = dot != std::string_view::npos && dot + 1 < domain.size();
  return hasNoSpace(value) && innerDot;
}

// scheme ":" rest, with an RFC 3986 scheme and no whitespace.
bool isUri(std::string_view value) {
  size_t colon = value.find(':');
  if (colon == std::string_view::npos || colon == 0 || !isAsciiLetter(value.front())) {
    return false;
  }
  bool schemeValid = allOf(value.substr(0, colon), [](char character) {
    return isAsciiLetter(character) || isAsciiDigit(character) || character == '+' || character == '.' ||
           character == '-';
  });
  return schemeValid && hasNoSpace(value);
}

bool isE164(std::string_view value) {
  bool shaped = value.size() >= 3 && value.size() <= 16 && value.front() == '+' && value[1] != '0';
  return shaped && allOf(value.substr(1), isAsciiDigit);
}

bool isHexColor(std::string_view value) {
  bool shaped = (value.size() == 4 || value.size() == 7) && value.front() == '#';
  return shaped && allOf(value.substr(1), isHexDigit);
}

bool isSlug(std::string_view value) {
  std::vector<std::string_view> parts = split(value, '-');
  return std::all_of(parts.begin(), parts.end(), [](std::string_view part) {
    return !part.empty() && allOf(part, [](char character) {
      return isAsciiDigit(character) || (character >= 'a' && character <= 'z');
    });
  });
}

bool isUppercaseCode(std::string_view value, size_t length) {
  return value.size() == length && allOf(value, [](char character) { return character >= 'A' && character <= 'Z'; });
}

bool isIpv4Octet(std::string_view part) {
  bool shaped = !part.empty() && part.size() <= 3 && allOf(part, isAsciiDigit) && (part.size() == 1 || part[0] != '0');
  return shaped && std::stoi(std::string(part)) <= 255;
}

bool isIpv4(std::string_view value) {
  std::vector<std::string_view> parts = split(value, '.');
  return parts.size() == 4 && std::all_of(parts.begin(), parts.end(), isIpv4Octet);
}

bool isHostnameLabel(std::string_view label) {
  bool shaped = !label.empty() && label.size() <= 63 && label.front() != '-' && label.back() != '-';
  return shaped && allOf(label, [](char character) {
    return isAsciiLetter(character) || isAsciiDigit(character) || character == '-';
  });
}

bool isHostname(std::string_view value) {
  std::vector<std::string_view> labels = split(value, '.');
  return !value.empty() && value.size() <= 253 && std::all_of(labels.begin(), labels.end(), isHostnameLabel);
}

const std::map<std::string_view, std::function<bool(std::string_view)>, std::less<>>& knownFormats() {
  static const std::map<std::string_view, std::function<bool(std::string_view)>, std::less<>> formats = {
      {"date-time", [](std::string_view value) { return timestampToMillis(value).has_value(); }},
      {"date", [](std::string_view value) { return dateToDays(value).has_value(); }},
      {"time", isRfc3339Time},
      {"uuid", [](std::string_view value) { return uuidTextToBytes(value).has_value(); }},
      {"email", isEmail},
      {"uri", isUri},
      {"url", isUri},
      {"e164", isE164},
      {"hex-color", isHexColor},
      {"slug", isSlug},
      {"iso4217", [](std::string_view value) { return isUppercaseCode(value, 3); }},
      {"iso3166-1-alpha2", [](std::string_view value) { return isUppercaseCode(value, 2); }},
      {"iso3166-1-alpha3", [](std::string_view value) { return isUppercaseCode(value, 3); }},
      {"ipv4", isIpv4},
      {"hostname", isHostname},
  };
  return formats;
}

}  // namespace

bool matchesFormat(std::string_view format, std::string_view value) {
  auto found = knownFormats().find(format);
  if (found == knownFormats().end()) {
    return true;
  }
  return found->second(value);
}

}  // namespace nw
