#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "bytes.hpp"
#include "status.hpp"

// Insertion-ordered so canonical serialisations are stable.
#include "nlohmann/json.hpp"

namespace nw {

using Json = nlohmann::ordered_json;

constexpr size_t kMaxJsonBytes = size_t{256} * 1024 * 1024;
constexpr size_t kMaxJsonDepth = 64;

// Rejects oversized or deeply nested input before handing it to the parser.
std::optional<Json> parseJson(std::string_view text);
std::string dumpCompact(const Json& value);

std::optional<std::string> readString(const Json& object, const char* key);
std::optional<std::string> readOptionalString(const Json& object, const char* key, bool& wellFormed);
std::optional<uint64_t> readUnsigned(const Json& object, const char* key);
std::optional<bool> readBool(const Json& object, const char* key);
std::optional<Bytes> readBytes(const Json& object, const char* key);
std::optional<Bytes> readOptionalBytes(const Json& object, const char* key, bool& wellFormed);
const Json* readArray(const Json& object, const char* key);
const Json* readObject(const Json& object, const char* key);

Json bytesToJson(ByteView bytes);

}  // namespace nw
