#include "json.hpp"

namespace nw {

namespace {

class NestingScanner {
 public:
  // Returns false once nesting exceeds the limit or closes more than it opened.
  bool consume(char character) {
    if (insideString_) {
      consumeStringCharacter(character);
      return true;
    }
    if (character == '"') {
      insideString_ = true;
    }
    if (character == '[' || character == '{') {
      ++depth_;
    }
    if (character == ']' || character == '}') {
      if (depth_ == 0) {
        return false;
      }
      --depth_;
    }
    return depth_ <= kMaxJsonDepth;
  }

 private:
  void consumeStringCharacter(char character) {
    if (escaped_) {
      escaped_ = false;
      return;
    }
    if (character == '\\') {
      escaped_ = true;
      return;
    }
    if (character == '"') {
      insideString_ = false;
    }
  }

  size_t depth_ = 0;
  bool insideString_ = false;
  bool escaped_ = false;
};

bool exceedsDepthLimit(std::string_view text) {
  NestingScanner scanner;
  for (char character : text) {
    if (!scanner.consume(character)) {
      return true;
    }
  }
  return false;
}

}  // namespace

std::optional<Json> parseJson(std::string_view text) {
  if (text.size() > kMaxJsonBytes || exceedsDepthLimit(text)) {
    return std::nullopt;
  }
  Json parsed = Json::parse(text.begin(), text.end(), nullptr, false);
  if (parsed.is_discarded()) {
    return std::nullopt;
  }
  return parsed;
}

std::string dumpCompact(const Json& value) { return value.dump(); }

std::optional<std::string> readString(const Json& object, const char* key) {
  if (!object.is_object() || !object.contains(key)) {
    return std::nullopt;
  }
  const Json& field = object.at(key);
  if (!field.is_string()) {
    return std::nullopt;
  }
  return field.get<std::string>();
}

std::optional<std::string> readOptionalString(const Json& object, const char* key, bool& wellFormed) {
  if (!object.is_object() || !object.contains(key) || object.at(key).is_null()) {
    return std::nullopt;
  }
  std::optional<std::string> value = readString(object, key);
  if (!value.has_value()) {
    wellFormed = false;
  }
  return value;
}

std::optional<uint64_t> readUnsigned(const Json& object, const char* key) {
  if (!object.is_object() || !object.contains(key)) {
    return std::nullopt;
  }
  const Json& field = object.at(key);
  if (!field.is_number_unsigned()) {
    return std::nullopt;
  }
  return field.get<uint64_t>();
}

std::optional<bool> readBool(const Json& object, const char* key) {
  if (!object.is_object() || !object.contains(key)) {
    return std::nullopt;
  }
  const Json& field = object.at(key);
  if (!field.is_boolean()) {
    return std::nullopt;
  }
  return field.get<bool>();
}

std::optional<Bytes> readBytes(const Json& object, const char* key) {
  std::optional<std::string> text = readString(object, key);
  if (!text.has_value()) {
    return std::nullopt;
  }
  return fromBase64Url(*text);
}

std::optional<Bytes> readOptionalBytes(const Json& object, const char* key, bool& wellFormed) {
  if (!object.is_object() || !object.contains(key) || object.at(key).is_null()) {
    return std::nullopt;
  }
  std::optional<Bytes> value = readBytes(object, key);
  if (!value.has_value()) {
    wellFormed = false;
  }
  return value;
}

const Json* readArray(const Json& object, const char* key) {
  if (!object.is_object() || !object.contains(key) || !object.at(key).is_array()) {
    return nullptr;
  }
  return &object.at(key);
}

const Json* readObject(const Json& object, const char* key) {
  if (!object.is_object() || !object.contains(key) || !object.at(key).is_object()) {
    return nullptr;
  }
  return &object.at(key);
}

Json bytesToJson(ByteView bytes) { return Json(toBase64Url(bytes)); }

}  // namespace nw
