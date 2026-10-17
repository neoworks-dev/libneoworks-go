#include "semver.hpp"

#include <vector>

#include "schema_values.hpp"
#include "wire.hpp"

namespace nw {

namespace {

std::optional<uint32_t> parsePart(std::string_view text) {
  std::optional<uint64_t> number = parseUnsignedDecimalText(text);
  if (!number.has_value() || *number > UINT32_MAX) {
    return std::nullopt;
  }
  return static_cast<uint32_t>(*number);
}

}  // namespace

std::optional<Semver> parseSemverText(std::string_view text) {
  size_t firstDot = text.find('.');
  if (firstDot == std::string_view::npos) {
    return std::nullopt;
  }
  size_t secondDot = text.find('.', firstDot + 1);
  if (secondDot == std::string_view::npos) {
    return std::nullopt;
  }
  std::optional<uint32_t> major = parsePart(text.substr(0, firstDot));
  std::optional<uint32_t> minor = parsePart(text.substr(firstDot + 1, secondDot - firstDot - 1));
  std::optional<uint32_t> patch = parsePart(text.substr(secondDot + 1));
  if (!major.has_value() || !minor.has_value() || !patch.has_value()) {
    return std::nullopt;
  }
  return Semver{*major, *minor, *patch};
}

std::string semverText(const Semver& version) {
  return std::to_string(version.major) + "." + std::to_string(version.minor) + "." + std::to_string(version.patch);
}

Bytes semverBody(const Semver& version) {
  wire::Writer writer;
  writer.varint(version.major);
  writer.varint(version.minor);
  writer.varint(version.patch);
  return writer.take();
}

std::optional<Semver> semverFromBody(ByteView body) {
  std::vector<uint64_t> parts;
  if (!wire::readPackedVarints(body, parts) || parts.size() != 3) {
    return std::nullopt;
  }
  for (uint64_t part : parts) {
    if (part > UINT32_MAX) {
      return std::nullopt;
    }
  }
  return Semver{static_cast<uint32_t>(parts[0]), static_cast<uint32_t>(parts[1]), static_cast<uint32_t>(parts[2])};
}

}  // namespace nw
