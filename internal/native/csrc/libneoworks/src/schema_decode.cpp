#include <bit>
#include <cmath>
#include <map>

#include "schema_codec.hpp"
#include "schema_codec_internal.hpp"
#include "schema_values.hpp"
#include "semver.hpp"

namespace nw {

namespace codec {

namespace {

using wire::WireType;

constexpr Status kMalformed = Status::Malformed;

// A oneof whose variant this reader does not know decodes to nothing; the field is omitted.
enum class Outcome { Failed, Value, Omitted };

using Occurrences = std::vector<wire::Field>;

std::optional<Json> decodeModel(const ModelDescriptor& model, ByteView bytes, const std::set<uint32_t>* fields,
                                Context& context);
Outcome readValue(const ValueShape& shape, const ValueConstraints& constraints, const wire::Field& field,
                  Context& context, Json& out);

const ValueConstraints& noConstraints() {
  static const ValueConstraints none;
  return none;
}

bool expectWire(const wire::Field& field, WireType type, Context& context) {
  if (field.type == type) {
    return true;
  }
  return context.fail(kMalformed, "unexpected wire type " + std::to_string(static_cast<int>(field.type)));
}

Outcome failed(bool) { return Outcome::Failed; }

Outcome produced(Json& out, Json value) {
  out = std::move(value);
  return Outcome::Value;
}

// ── Scalars ───────────────────────────────────────────────────────────────────

Outcome readNarrowInteger(const IntegerRange& range, const ValueConstraints& constraints, const wire::Field& field,
                          Context& context, Json& out) {
  if (!expectWire(field, WireType::Varint, context)) {
    return Outcome::Failed;
  }
  if (!range.isSigned) {
    if (field.number > range.maximum) {
      return failed(context.fail(kMalformed, "integer is out of range"));
    }
    if (!checkConstraints(constraints, static_cast<double>(field.number), context, kMalformed)) {
      return Outcome::Failed;
    }
    return produced(out, Json(field.number));
  }
  int64_t number = static_cast<int64_t>(field.number);
  if (number < range.minimum || number > static_cast<int64_t>(range.maximum)) {
    return failed(context.fail(kMalformed, "integer is out of range"));
  }
  if (!checkConstraints(constraints, static_cast<double>(number), context, kMalformed)) {
    return Outcome::Failed;
  }
  return produced(out, Json(number));
}

Outcome readWideInteger(Scalar scalar, const ValueConstraints& constraints, const wire::Field& field, Context& context,
                        Json& out) {
  if (!expectWire(field, WireType::Varint, context)) {
    return Outcome::Failed;
  }
  if (scalar == Scalar::U64) {
    if (!checkConstraints(constraints, static_cast<double>(field.number), context, kMalformed)) {
      return Outcome::Failed;
    }
    return produced(out, Json(std::to_string(field.number)));
  }
  int64_t number = static_cast<int64_t>(field.number);
  if (!checkConstraints(constraints, static_cast<double>(number), context, kMalformed)) {
    return Outcome::Failed;
  }
  return produced(out, Json(std::to_string(number)));
}

Outcome readFloat(const ValueConstraints& constraints, const wire::Field& field, Context& context, Json& out) {
  double number = 0;
  if (field.type == WireType::I32) {
    number = std::bit_cast<float>(static_cast<uint32_t>(field.number));
  } else if (expectWire(field, WireType::I64, context)) {
    number = std::bit_cast<double>(field.number);
  } else {
    return Outcome::Failed;
  }
  if (!std::isfinite(number)) {
    return failed(context.fail(kMalformed, "number is not finite"));
  }
  if (!checkConstraints(constraints, number, context, kMalformed)) {
    return Outcome::Failed;
  }
  return produced(out, Json(number));
}

Outcome readText(const ValueConstraints& constraints, const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  std::string text(field.body.begin(), field.body.end());
  if (!checkConstraints(constraints, text, context, kMalformed)) {
    return Outcome::Failed;
  }
  return produced(out, Json(std::move(text)));
}

Outcome readBinary(const ValueConstraints& constraints, const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  if (!checkConstraints(constraints, field.body, context, kMalformed)) {
    return Outcome::Failed;
  }
  return produced(out, Json(toBase64Url(field.body)));
}

Outcome readUuid(const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  std::optional<std::string> text = uuidBytesToText(field.body);
  if (!text.has_value()) {
    return failed(context.fail(kMalformed, "a uuid must be 16 bytes"));
  }
  return produced(out, Json(*text));
}

Outcome readJsonValue(const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  std::optional<Json> value = parseJson(std::string_view(reinterpret_cast<const char*>(field.body.data()), field.body.size()));
  if (!value.has_value()) {
    return failed(context.fail(kMalformed, "json value does not parse"));
  }
  return produced(out, std::move(*value));
}

Outcome readSemver(const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  std::optional<Semver> version = semverFromBody(field.body);
  if (!version.has_value()) {
    return failed(context.fail(kMalformed, "a semver must be three varints of at most 32 bits"));
  }
  return produced(out, Json(semverText(*version)));
}

std::optional<std::string> formatTemporal(Scalar scalar, int64_t number) {
  if (scalar == Scalar::Date) {
    return daysToDate(number);
  }
  if (scalar == Scalar::Time) {
    return nanosToTime(number);
  }
  return millisToTimestamp(number);
}

Outcome readTemporal(Scalar scalar, const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Varint, context)) {
    return Outcome::Failed;
  }
  std::optional<std::string> text = formatTemporal(scalar, static_cast<int64_t>(field.number));
  if (!text.has_value()) {
    return failed(context.fail(kMalformed, "date or time is out of range"));
  }
  return produced(out, Json(*text));
}

Outcome readScalar(Scalar scalar, const ValueConstraints& constraints, const wire::Field& field, Context& context,
                   Json& out) {
  if (std::optional<IntegerRange> range = narrowIntegerRange(scalar)) {
    return readNarrowInteger(*range, constraints, field, context, out);
  }
  if (isWideInteger(scalar)) {
    return readWideInteger(scalar, constraints, field, context, out);
  }
  switch (scalar) {
    case Scalar::Bool:
      if (!expectWire(field, WireType::Varint, context)) {
        return Outcome::Failed;
      }
      return produced(out, Json(field.number != 0));
    case Scalar::F32:
    case Scalar::F64:
      return readFloat(constraints, field, context, out);
    case Scalar::String:
      return readText(constraints, field, context, out);
    case Scalar::Binary:
      return readBinary(constraints, field, context, out);
    case Scalar::Uuid:
      return readUuid(field, context, out);
    case Scalar::JsonValue:
      return readJsonValue(field, context, out);
    case Scalar::Semver:
      return readSemver(field, context, out);
    default:
      return readTemporal(scalar, field, context, out);
  }
}

// ── Enums, decimals, messages, oneofs ─────────────────────────────────────────

Outcome readEnum(const EnumDescriptor& enumType, const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Varint, context)) {
    return Outcome::Failed;
  }
  const EnumVariantDescriptor* variant = enumType.variantByOrdinal(field.number);
  if (variant == nullptr) {
    return produced(out, Json(field.number));
  }
  return produced(out, Json(variant->name));
}

Outcome readDecimal(const ValueShape& shape, const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  std::string text(field.body.begin(), field.body.end());
  std::optional<std::string> canonical = canonicalDecimal(text, shape.precision, shape.scale);
  if (!canonical.has_value()) {
    return failed(context.fail(kMalformed, "decimal does not fit its precision and scale"));
  }
  return produced(out, Json(*canonical));
}

Outcome readNested(const ModelDescriptor& model, const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  std::optional<Json> object = decodeModel(model, field.body, nullptr, context);
  if (!object.has_value()) {
    return Outcome::Failed;
  }
  return produced(out, std::move(*object));
}

const OneofVariantDescriptor* variantByOrdinal(const ValueShape& shape, uint32_t ordinal) {
  for (const OneofVariantDescriptor& variant : shape.variants) {
    if (variant.ordinal == ordinal) {
      return &variant;
    }
  }
  return nullptr;
}

Outcome readVariant(const OneofVariantDescriptor& variant, const wire::Field& inner, Context& context, Json& out) {
  PathSegment segment(context, fieldSegment(variant.name));
  Json value;
  Outcome outcome = readValue(variant.value, noConstraints(), inner, context, value);
  if (outcome != Outcome::Value) {
    return outcome;
  }
  Json object = Json::object();
  object[variant.name] = std::move(value);
  return produced(out, std::move(object));
}

// The first variant this reader knows wins, as in the TS decoder.
Outcome readOneof(const ValueShape& shape, const wire::Field& field, Context& context, Json& out) {
  if (!expectWire(field, WireType::Len, context)) {
    return Outcome::Failed;
  }
  wire::Reader reader(field.body);
  while (!reader.atEnd()) {
    wire::Field inner;
    if (reader.next(inner) != Status::Ok) {
      return failed(context.fail(kMalformed, "oneof is malformed"));
    }
    const OneofVariantDescriptor* variant = variantByOrdinal(shape, inner.ordinal);
    if (variant != nullptr) {
      return readVariant(*variant, inner, context, out);
    }
  }
  return Outcome::Omitted;
}

Outcome readValue(const ValueShape& shape, const ValueConstraints& constraints, const wire::Field& field,
                  Context& context, Json& out) {
  switch (shape.kind) {
    case ValueKind::Scalar:
      return readScalar(shape.scalar, constraints, field, context, out);
    case ValueKind::Enum:
      return readEnum(*shape.enumType, field, context, out);
    case ValueKind::Decimal:
      return readDecimal(shape, field, context, out);
    case ValueKind::Message:
    case ValueKind::File:
    case ValueKind::Reference:
      return readNested(*shape.model, field, context, out);
    case ValueKind::Oneof:
      return readOneof(shape, field, context, out);
  }
  return Outcome::Failed;
}

// ── Lists and maps ────────────────────────────────────────────────────────────

// Splits a packed LEN body into one synthetic field per element.
bool unpack(const FieldDescriptor& field, const wire::Field& packed, Context& context, Occurrences& elements) {
  WireType elementType = wireTypeOf(field.value);
  std::vector<uint64_t> numbers;
  bool unpacked = false;
  if (elementType == WireType::I64) {
    unpacked = wire::readPackedFixed64(packed.body, numbers);
  } else {
    unpacked = wire::readPackedVarints(packed.body, numbers);
  }
  if (!unpacked) {
    return context.fail(kMalformed, "packed list is malformed");
  }
  for (uint64_t number : numbers) {
    wire::Field element;
    element.ordinal = packed.ordinal;
    element.type = elementType;
    element.number = number;
    elements.push_back(element);
  }
  return true;
}

// The list's elements, accepting packed and unpacked encodings of packable values.
bool listElements(const FieldDescriptor& field, const Occurrences& occurrences, Context& context,
                  Occurrences& elements) {
  bool packable = wireTypeOf(field.value) != WireType::Len;
  for (const wire::Field& occurrence : occurrences) {
    if (packable && occurrence.type == WireType::Len && !unpack(field, occurrence, context, elements)) {
      return false;
    }
    if (!packable || occurrence.type != WireType::Len) {
      elements.push_back(occurrence);
    }
  }
  return true;
}

bool readList(const FieldDescriptor& field, const Occurrences& occurrences, Context& context, Json& out) {
  Occurrences elements;
  if (!listElements(field, occurrences, context, elements)) {
    return false;
  }
  out = Json::array();
  for (size_t index = 0; index < elements.size(); ++index) {
    PathSegment segment(context, indexSegment(index));
    Json value;
    Outcome outcome = readValue(field.value, field.constraints, elements[index], context, value);
    if (outcome == Outcome::Failed) {
      return false;
    }
    if (outcome == Outcome::Value) {
      out.push_back(std::move(value));
    }
  }
  return true;
}

std::string_view bodyText(const wire::Field& field) {
  return std::string_view(reinterpret_cast<const char*>(field.body.data()), field.body.size());
}

std::optional<std::string> mapKeyText(Scalar scalar, const wire::Field& key) {
  if (scalar == Scalar::String && key.type == WireType::Len && countCodePoints(bodyText(key)).has_value()) {
    return std::string(bodyText(key));
  }
  if (scalar == Scalar::Uuid && key.type == WireType::Len) {
    return uuidBytesToText(key.body);
  }
  if (key.type != WireType::Varint || scalar == Scalar::String || scalar == Scalar::Uuid) {
    return std::nullopt;
  }
  if (scalar == Scalar::Bool && key.number != 0) {
    return std::string("true");
  }
  if (scalar == Scalar::Bool) {
    return std::string("false");
  }
  std::optional<IntegerRange> range = narrowIntegerRange(scalar);
  bool isSigned = scalar == Scalar::I64 || (range.has_value() && range->isSigned);
  if (isSigned) {
    return std::to_string(static_cast<int64_t>(key.number));
  }
  return std::to_string(key.number);
}

bool readMapEntry(const FieldDescriptor& field, const wire::Field& entry, Context& context, Json& out) {
  if (!expectWire(entry, WireType::Len, context)) {
    return false;
  }
  wire::Reader reader(entry.body);
  std::optional<wire::Field> key;
  std::optional<wire::Field> value;
  while (!reader.atEnd()) {
    wire::Field inner;
    if (reader.next(inner) != Status::Ok) {
      return context.fail(kMalformed, "map entry is malformed");
    }
    if (inner.ordinal == 1) {
      key = inner;
    }
    if (inner.ordinal == 2) {
      value = inner;
    }
  }
  if (!key.has_value() || !value.has_value()) {
    return true;
  }
  std::optional<std::string> keyText = mapKeyText(field.container.mapKey, *key);
  if (!keyText.has_value()) {
    return context.fail(kMalformed, "map key does not fit the key type");
  }
  PathSegment segment(context, keySegment(*keyText));
  Json decoded;
  Outcome outcome = readValue(field.value, field.constraints, *value, context, decoded);
  if (outcome == Outcome::Value) {
    out[*keyText] = std::move(decoded);
  }
  return outcome != Outcome::Failed;
}

bool readMap(const FieldDescriptor& field, const Occurrences& entries, Context& context, Json& out) {
  out = Json::object();
  for (const wire::Field& entry : entries) {
    if (!readMapEntry(field, entry, context, out)) {
      return false;
    }
  }
  return true;
}

// The tag 1 fields inside a wrapper message.
bool unwrap(const wire::Field& wrapper, Context& context, Occurrences& inner) {
  if (!expectWire(wrapper, WireType::Len, context)) {
    return false;
  }
  wire::Reader reader(wrapper.body);
  while (!reader.atEnd()) {
    wire::Field field;
    if (reader.next(field) != Status::Ok) {
      return context.fail(kMalformed, "wrapper is malformed");
    }
    if (field.ordinal == 1) {
      inner.push_back(field);
    }
  }
  return true;
}

// ── Fields ────────────────────────────────────────────────────────────────────

// False on failure; `present` tells whether `out` holds a value.
bool readSingular(const FieldDescriptor& field, const Occurrences& occurrences, Context& context, Json& out,
                  bool& present) {
  if (occurrences.empty()) {
    if (field.required) {
      return context.fail(kMalformed, "required field is absent");
    }
    return true;
  }
  Outcome outcome = readValue(field.value, field.constraints, occurrences.back(), context, out);
  present = outcome == Outcome::Value;
  return outcome != Outcome::Failed;
}

bool readWrapped(const FieldDescriptor& field, const Occurrences& occurrences, Context& context, Json& out,
                 bool& present) {
  if (occurrences.empty()) {
    return true;
  }
  Occurrences inner;
  if (!unwrap(occurrences.back(), context, inner)) {
    return false;
  }
  present = true;
  if (field.container.kind == ContainerKind::WrapperMap) {
    return readMap(field, inner, context, out);
  }
  return readList(field, inner, context, out);
}

bool readField(const FieldDescriptor& field, const Occurrences& occurrences, Context& context, Json& out,
               bool& present) {
  switch (field.container.kind) {
    case ContainerKind::Singular:
      return readSingular(field, occurrences, context, out, present);
    case ContainerKind::RepeatedPacked:
    case ContainerKind::RepeatedLen:
      present = true;
      return readList(field, occurrences, context, out);
    case ContainerKind::Map:
      present = true;
      return readMap(field, occurrences, context, out);
    default:
      return readWrapped(field, occurrences, context, out, present);
  }
}

bool groupFields(const ModelDescriptor& model, ByteView bytes, const std::set<uint32_t>* fields, Context& context,
                 std::map<uint32_t, Occurrences>& grouped) {
  wire::Reader reader(bytes);
  while (!reader.atEnd()) {
    wire::Field field;
    if (reader.next(field) != Status::Ok) {
      return context.fail(kMalformed, "message is malformed");
    }
    const FieldDescriptor* known = model.fieldByOrdinal(field.ordinal);
    if (known != nullptr && fields != nullptr && fields->count(field.ordinal) == 0) {
      return context.fail(kMalformed, "field " + known->name + " is stored in the wrong facet");
    }
    if (known != nullptr) {
      grouped[field.ordinal].push_back(field);
    }
  }
  return true;
}

bool decodeModelField(const FieldDescriptor& field, const std::map<uint32_t, Occurrences>& grouped, Context& context,
                      Json& object) {
  PathSegment segment(context, fieldSegment(field.name));
  Occurrences occurrences;
  auto found = grouped.find(field.ordinal);
  if (found != grouped.end()) {
    occurrences = found->second;
  }
  Json value;
  bool present = false;
  if (!readField(field, occurrences, context, value, present)) {
    return false;
  }
  if (present) {
    object[field.name] = std::move(value);
  }
  return true;
}

std::optional<Json> decodeModel(const ModelDescriptor& model, ByteView bytes, const std::set<uint32_t>* fields,
                                Context& context) {
  std::map<uint32_t, Occurrences> grouped;
  if (!context.enter() || !groupFields(model, bytes, fields, context, grouped)) {
    return std::nullopt;
  }
  Json object = Json::object();
  for (const FieldDescriptor& field : model.fields) {
    bool selected = fields == nullptr || fields->count(field.ordinal) != 0;
    if (selected && !decodeModelField(field, grouped, context, object)) {
      return std::nullopt;
    }
  }
  context.leave();
  return object;
}

}  // namespace

}  // namespace codec

Result<Json> decodeMessage(const ModelDescriptor& model, ByteView bytes, const std::set<uint32_t>* fields,
                           CodecError& error) {
  error = CodecError{};
  codec::Context context(error, model.name);
  std::optional<Json> object = codec::decodeModel(model, bytes, fields, context);
  if (!object.has_value()) {
    return error.status;
  }
  return std::move(*object);
}

}  // namespace nw
