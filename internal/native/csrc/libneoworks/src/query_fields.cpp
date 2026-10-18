#include "query_fields.hpp"

#include <algorithm>
#include <cctype>

#include "schema_values.hpp"
#include "timeutil.hpp"

namespace nw {

namespace {

bool isIntegerScalar(Scalar scalar) {
  return scalar == Scalar::I8 || scalar == Scalar::I16 || scalar == Scalar::I32 || scalar == Scalar::I64 ||
         scalar == Scalar::U8 || scalar == Scalar::U16 || scalar == Scalar::U32 || scalar == Scalar::U64;
}

std::optional<FieldType> scalarType(Scalar scalar) {
  if (isIntegerScalar(scalar)) {
    return FieldType::Integer;
  }
  if (scalar == Scalar::F32 || scalar == Scalar::F64) {
    return FieldType::Real;
  }
  if (scalar == Scalar::Bool) {
    return FieldType::Boolean;
  }
  if (scalar == Scalar::String) {
    return FieldType::Text;
  }
  if (scalar == Scalar::Uuid) {
    return FieldType::Identifier;
  }
  if (scalar == Scalar::Timestamp) {
    return FieldType::Timestamp;
  }
  if (scalar == Scalar::Date) {
    return FieldType::Date;
  }
  if (scalar == Scalar::Time) {
    return FieldType::Time;
  }
  if (scalar == Scalar::Duration) {
    return FieldType::Duration;
  }
  return std::nullopt;
}

Comparable integerValue(int64_t value) {
  Comparable comparable;
  comparable.kind = Comparable::Kind::Integer;
  comparable.integer.negative = value < 0;
  if (value < 0) {
    comparable.integer.magnitude = uint64_t{0} - static_cast<uint64_t>(value);
  } else {
    comparable.integer.magnitude = static_cast<uint64_t>(value);
  }
  return comparable;
}

Comparable textValue(std::string text, Comparable::Kind kind) {
  Comparable comparable;
  comparable.kind = kind;
  comparable.text = std::move(text);
  return comparable;
}

std::optional<Comparable> integerFromText(const std::string& text) {
  std::optional<int64_t> signedValue = parseSignedDecimalText(text);
  if (signedValue.has_value()) {
    return integerValue(*signedValue);
  }
  std::optional<uint64_t> unsignedValue = parseUnsignedDecimalText(text);
  if (!unsignedValue.has_value()) {
    return std::nullopt;
  }
  Comparable comparable;
  comparable.kind = Comparable::Kind::Integer;
  comparable.integer.magnitude = *unsignedValue;
  return comparable;
}

// Integers appear as JSON numbers or, when they may exceed 2^53, as decimal strings.
std::optional<Comparable> toInteger(const Json& value) {
  if (value.is_number_unsigned()) {
    return integerFromText(std::to_string(value.get<uint64_t>()));
  }
  if (value.is_number_integer()) {
    return integerValue(value.get<int64_t>());
  }
  if (value.is_string()) {
    return integerFromText(value.get<std::string>());
  }
  return std::nullopt;
}

std::optional<Comparable> toReal(const Json& value) {
  if (!value.is_number()) {
    return std::nullopt;
  }
  Comparable comparable;
  comparable.kind = Comparable::Kind::Real;
  comparable.real = value.get<double>();
  return comparable;
}

std::optional<Comparable> toDecimal(const Json& value, const ValueShape& shape) {
  std::string text;
  if (value.is_string()) {
    text = value.get<std::string>();
  } else if (value.is_number()) {
    text = value.dump();
  } else {
    return std::nullopt;
  }
  std::optional<std::string> canonical = canonicalDecimal(text, shape.precision, shape.scale);
  if (!canonical.has_value()) {
    return std::nullopt;
  }
  return textValue(*canonical, Comparable::Kind::Decimal);
}

std::optional<Comparable> toEnumOrdinal(const std::string& name, const ValueShape& shape) {
  const EnumVariantDescriptor* variant = shape.enumType->variantByName(name);
  if (variant == nullptr) {
    return std::nullopt;
  }
  return integerValue(variant->ordinal);
}

std::optional<int64_t> instantMillis(const std::string& text) {
  std::optional<int64_t> exact = timestampToMillis(text);
  if (exact.has_value()) {
    return exact;
  }
  std::optional<int64_t> seconds = parseInstant(text);
  if (!seconds.has_value()) {
    return std::nullopt;
  }
  return *seconds * 1000;
}

std::optional<Comparable> fromString(const std::string& text, FieldType type, const ValueShape& shape) {
  std::optional<int64_t> number;
  if (type == FieldType::Text) {
    return textValue(text, Comparable::Kind::Text);
  }
  if (type == FieldType::Enum) {
    return toEnumOrdinal(text, shape);
  }
  if (type == FieldType::Identifier) {
    std::optional<Bytes> bytes = uuidTextToBytes(text);
    if (!bytes.has_value()) {
      return std::nullopt;
    }
    return textValue(uuidBytesToText(*bytes).value(), Comparable::Kind::Text);
  }
  if (type == FieldType::Timestamp) {
    number = instantMillis(text);
  } else if (type == FieldType::Date) {
    number = dateToDays(text);
  } else if (type == FieldType::Time) {
    number = timeToNanos(text);
  }
  if (!number.has_value()) {
    return std::nullopt;
  }
  return integerValue(*number);
}

}  // namespace

std::string lowercaseAscii(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  return text;
}

std::optional<FieldType> valueType(const FieldDescriptor& field) {
  if (field.value.kind == ValueKind::Enum) {
    return FieldType::Enum;
  }
  if (field.value.kind == ValueKind::Decimal) {
    return FieldType::Decimal;
  }
  if (field.value.kind == ValueKind::Reference) {
    return FieldType::Identifier;
  }
  if (field.value.kind == ValueKind::Scalar) {
    return scalarType(field.value.scalar);
  }
  return std::nullopt;
}

std::optional<FieldType> filterableType(const FieldDescriptor& field) {
  if (field.container.kind != ContainerKind::Singular) {
    return std::nullopt;
  }
  return valueType(field);
}

bool isList(const FieldDescriptor& field) {
  ContainerKind kind = field.container.kind;
  return kind == ContainerKind::RepeatedPacked || kind == ContainerKind::RepeatedLen ||
         kind == ContainerKind::WrapperRepeated;
}

bool isMap(const FieldDescriptor& field) {
  return field.container.kind == ContainerKind::Map || field.container.kind == ContainerKind::WrapperMap;
}

bool isFile(const FieldDescriptor& field) { return field.value.kind == ValueKind::File; }

bool isMessage(const FieldDescriptor& field) {
  return field.value.kind == ValueKind::Message && field.value.model != nullptr;
}

bool isFilterableFileMember(const FieldDescriptor& member) {
  return member.ordinal == kFileNameOrdinal || member.ordinal == kFileMediaTypeOrdinal ||
         member.ordinal == kFileSizeOrdinal;
}

bool isOrdered(FieldType type) {
  return type != FieldType::Boolean && type != FieldType::Identifier && type != FieldType::Enum;
}

std::optional<Comparable> toComparable(const Json& value, const FieldDescriptor& field, FieldType type) {
  if (type == FieldType::Boolean) {
    if (!value.is_boolean()) {
      return std::nullopt;
    }
    Comparable comparable;
    comparable.kind = Comparable::Kind::Boolean;
    comparable.boolean = value.get<bool>();
    return comparable;
  }
  if (type == FieldType::Integer || type == FieldType::Duration) {
    return toInteger(value);
  }
  if (type == FieldType::Real) {
    return toReal(value);
  }
  if (type == FieldType::Decimal) {
    return toDecimal(value, field.value);
  }
  if (!value.is_string()) {
    return std::nullopt;
  }
  return fromString(value.get<std::string>(), type, field.value);
}

namespace {

// Content nested deeper than this is not indexed.
constexpr size_t kMaxIndexedDepth = 32;

IndexedMessage messageOf(const ModelDescriptor& model, const Json& content, size_t depth);

IndexedMessage fileMessageOf(const Json& file) {
  IndexedMessage message;
  if (!file.is_object()) {
    return message;
  }
  for (const FieldDescriptor& member : fileModel().fields) {
    auto value = file.find(member.name);
    if (!isFilterableFileMember(member) || value == file.end()) {
      continue;
    }
    std::optional<Comparable> comparable = toComparable(*value, member, *filterableType(member));
    if (comparable.has_value()) {
      message.values.emplace(member.ordinal, std::move(*comparable));
    }
  }
  return message;
}

IndexedMessage plainValueMessageOf(const FieldDescriptor& field, const Json& value) {
  IndexedMessage message;
  std::optional<Comparable> comparable = toComparable(value, field, *valueType(field));
  if (comparable.has_value()) {
    message.values.emplace(kWholeValue, std::move(*comparable));
  }
  return message;
}

bool isNested(const FieldDescriptor& field) { return isFile(field) || isMessage(field); }

bool isIndexed(const FieldDescriptor& field) { return isNested(field) || valueType(field).has_value(); }

// What one File, message or plain value of `field` becomes.
IndexedMessage elementMessageOf(const FieldDescriptor& field, const Json& value, size_t depth) {
  if (isFile(field)) {
    return fileMessageOf(value);
  }
  if (isMessage(field)) {
    return messageOf(*field.value.model, value, depth + 1);
  }
  return plainValueMessageOf(field, value);
}

void addSingular(const FieldDescriptor& field, const Json& value, size_t depth, IndexedMessage& into) {
  if (isNested(field)) {
    IndexedMessage nested = elementMessageOf(field, value, depth);
    if (!nested.empty()) {
      into.messages.emplace(field.ordinal, std::move(nested));
    }
    return;
  }
  std::optional<Comparable> comparable = toComparable(value, field, *valueType(field));
  if (comparable.has_value()) {
    into.values.emplace(field.ordinal, std::move(*comparable));
  }
}

// The elements of a list, or the values of a map, which JSON writes as an array or an object.
void addCollection(const FieldDescriptor& field, const Json& value, size_t depth, IndexedMessage& into) {
  if (!value.is_array() && !value.is_object()) {
    return;
  }
  std::vector<IndexedMessage> elements;
  for (const Json& element : value) {
    if (!element.is_null()) {
      elements.push_back(elementMessageOf(field, element, depth));
    }
  }
  if (!elements.empty()) {
    into.lists.emplace(field.ordinal, std::move(elements));
  }
}

IndexedMessage messageOf(const ModelDescriptor& model, const Json& content, size_t depth) {
  IndexedMessage message;
  if (!content.is_object() || depth > kMaxIndexedDepth) {
    return message;
  }
  for (const FieldDescriptor& field : model.fields) {
    auto value = content.find(field.name);
    if (value == content.end() || value->is_null() || !isIndexed(field)) {
      continue;
    }
    if (field.container.kind == ContainerKind::Singular) {
      addSingular(field, *value, depth, message);
    } else {
      addCollection(field, *value, depth, message);
    }
  }
  return message;
}

}  // namespace

IndexedMessage indexedMessageOf(const ModelDescriptor& model, const Json& content) {
  return messageOf(model, content, 0);
}

}  // namespace nw
