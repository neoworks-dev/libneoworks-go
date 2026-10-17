#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "bytes.hpp"

// The OpenSchema `semver` type: three unsigned 32-bit numbers, compared as integers, with
// no pre-release or build suffix. On the wire it is a LEN body of three varints.
namespace nw {

struct Semver {
  uint32_t major = 0;
  uint32_t minor = 0;
  uint32_t patch = 0;

  auto operator<=>(const Semver&) const = default;
};

// "major.minor.patch" without leading zeros, e.g. "0.6.1".
std::optional<Semver> parseSemverText(std::string_view text);
std::string semverText(const Semver& version);

// The LEN body: exactly three varints, major then minor then patch.
Bytes semverBody(const Semver& version);
std::optional<Semver> semverFromBody(ByteView body);

}  // namespace nw
