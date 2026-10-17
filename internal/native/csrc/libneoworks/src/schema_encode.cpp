#include <algorithm>
#include <bit>
#include <cfloat>
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
using wire::Writer;

constexpr Status kInvalid = Status::InvalidArgument;

struct Chunk {
  uint32_t ordinal;
  Bytes bytes;
};

using PreviousFields = std::map<uint32_t, std::vector<wire::Field>>;

const ValueConstraints& noConstraints() {
  static const ValueConstraints none;
  return none;
}

bool writeValue(const ValueShape& shape, const ValueConstraints& constraints, const Json& value, ByteView previousBody,
                Context& context, Writer& writer);
bool encodeModel(const ModelDescriptor& model, const Json& object, const EncodeOptions& options, Context& context,
                 Bytes& out);

// ── Scalars ───────────────────────────────────────────────────────────────────

std::optional<int64_t> readNarrowInteger(const Json& value, const IntegerRange& range) {
  if (value.is_number_unsigned()) {
    uint64_t number = value.get<uint64_t>();
    if (number > range.maximum) {
      return std::nullopt;
    }
    return static_cast<int64_t>(number);
  }
  if (value.is_number_integer()) {
    int64_t number = value.get<int64_t>();
    bool inRange = number >= range.minimum && (number < 0 || static_cast<uint64_t>(number) <= range.maximum);
    if (!inRange) {
      return std::nullopt;
    }
    return number;
  }
  double number = value.get<double>();
  bool integral = std::isfinite(number) && std::trunc(number) == number;
  if (!integral || number < static_cast<double>(range.minimum) || number > static_cast<double>(range.maximum)) {
    return std::nullopt;
  }
  return static_cast<int64_t>(number);
}

bool writeNarrowInteger(const IntegerRange& range, const ValueConstraints& constraints, const Json& value,
                        Context& context, Writer& writer) {
  if (!value.is_number()) {
    return context.fail(kInvalid, "expected an integer");
  }
  std::optional<int64_t> number = readNarrowInteger(value, range);
  if (!number.has_value()) {
    return context.fail(kInvalid, "expected an integer in range");
  }
  if (!checkConstraints(constraints, static_cast<double>(*number), context, kInvalid)) {
    return false;
  }
  writer.varint(static_cast<uint64_t>(*number));
  return true;
}

bool writeWideInteger(Scalar scalar, const ValueConstraints& constraints, const Json& value, Context& context,
                      Writer& writer) {
  if (!value.is_string()) {
    return context.fail(kInvalid, "expected a decimal string");
  }
  const std::string& text = value.get_ref<const std::string&>();
  if (scalar == Scalar::U64) {
    std::optional<uint64_t> number = parseUnsignedDecimalText(text);
    if (!number.has_value()) {
      return context.fail(kInvalid, "expected an unsigned 64-bit decimal string");
    }
    writer.varint(*number);
    return checkConstraints(constraints, static_cast<double>(*number), context, kInvalid);
  }
  std::optional<int64_t> number = parseSignedDecimalText(text);
  if (!number.has_value()) {
    return context.fail(kInvalid, "expected a signed 64-bit decimal string");
  }
  writer.varint(static_cast<uint64_t>(*number));
  return checkConstraints(constraints, static_cast<double>(*number), context, kInvalid);
}

bool writeFloat(Scalar scalar, const ValueConstraints& constraints, const Json& value, Context& context,
                Writer& writer) {
  if (!value.is_number()) {
    return context.fail(kInvalid, "expected a number");
  }
  double number = value.get<double>();
  if (!std::isfinite(number) || (scalar == Scalar::F32 && std::fabs(number) > FLT_MAX)) {
    return context.fail(kInvalid, "number is out of range");
  }
  writer.fixed64(std::bit_cast<uint64_t>(number));
  return checkConstraints(constraints, number, context, kInvalid);
}

bool writeText(const ValueConstraints& constraints, const Json& value, Context& context, Writer& writer) {
  if (!value.is_string()) {
    return context.fail(kInvalid, "expected a string");
  }
  const std::string& text = value.get_ref<const std::string&>();
  if (!checkConstraints(constraints, text, context, kInvalid)) {
    return false;
  }
  writer.lengthDelimited(viewOf(text));
  return true;
}

bool writeBinary(const ValueConstraints& constraints, const Json& value, Context& context, Writer& writer) {
  std::optional<Bytes> bytes;
  if (value.is_string()) {
    bytes = fromBase64Url(value.get_ref<const std::string&>());
  }
  if (!bytes.has_value()) {
    return context.fail(kInvalid, "expected base64url without padding");
  }
  if (!checkConstraints(constraints, ByteView(*bytes), context, kInvalid)) {
    return false;
  }
  writer.lengthDelimited(*bytes);
  return true;
}

bool writeUuid(const Json& value, Context& context, Writer& writer) {
  std::optional<Bytes> bytes;
  if (value.is_string()) {
    bytes = uuidTextToBytes(value.get_ref<const std::string&>());
  }
  if (!bytes.has_value()) {
    return context.fail(kInvalid, "expected a uuid");
  }
  writer.lengthDelimited(*bytes);
  return true;
}

bool writeSemver(const Json& value, Context& context, Writer& writer) {
  std::optional<Semver> version;
  if (value.is_string()) {
    version = parseSemverText(value.get_ref<const std::string&>());
  }
  if (!version.has_value()) {
    return context.fail(kInvalid, "expected a version major.minor.patch, each part a 32-bit number");
  }
  writer.lengthDelimited(semverBody(*version));
  return true;
}

std::optional<int64_t> parseTemporal(Scalar scalar, const std::string& text) {
  if (scalar == Scalar::Date) {
    return dateToDays(text);
  }
  if (scalar == Scalar::Time) {
    return timeToNanos(text);
  }
  return timestampToMillis(text);
}

bool writeTemporal(Scalar scalar, const Json& value, Context& context, Writer& writer) {
  std::optional<int64_t> number;
  if (value.is_string()) {
    number = parseTemporal(scalar, value.get_ref<const std::string&>());
  }
  if (!number.has_value()) {
    return context.fail(kInvalid, "expected an ISO 8601 date, time or timestamp of the field's type");
  }
  writer.varint(static_cast<uint64_t>(*number));
  return true;
}

bool writeScalar(Scalar scalar, const ValueConstraints& constraints, const Json& value, Context& context,
                 Writer& writer) {
  if (std::optional<IntegerRange> range = narrowIntegerRange(scalar)) {
    return writeNarrowInteger(*range, constraints, value, context, writer);
  }
  if (isWideInteger(scalar)) {
    return writeWideInteger(scalar, constraints, value, context, writer);
  }
  switch (scalar) {
    case Scalar::Bool:
      if (!value.is_boolean()) {
        return context.fail(kInvalid, "expected a boolean");
      }
      writer.varint(static_cast<uint64_t>(value.get<bool>()));
      return true;
    case Scalar::F32:
    case Scalar::F64:
      return writeFloat(scalar, constraints, value, context, writer);
    case Scalar::String:
      return writeText(constraints, value, context, writer);
    case Scalar::Binary:
      return writeBinary(constraints, value, context, writer);
    case Scalar::Uuid:
      return writeUuid(value, context, writer);
    case Scalar::JsonValue:
      writer.lengthDelimited(viewOf(canonicalJsonText(value)));
      return true;
    case Scalar::Semver:
      return writeSemver(value, context, writer);
    default:
      return writeTemporal(scalar, value, context, writer);
  }
}

// ── Enums, decimals, messages, oneofs ─────────────────────────────────────────

bool writeEnum(const EnumDescriptor& enumType, const Json& value, Context& context, Writer& writer) {
  if (value.is_number_unsigned() && value.get<uint64_t>() <= UINT32_MAX) {
    writer.varint(value.get<uint64_t>());
    return true;
  }
  const EnumVariantDescriptor* variant = nullptr;
  if (value.is_string()) {
    variant = enumType.variantByName(value.get_ref<const std::string&>());
  }
  if (variant == nullptr) {
    return context.fail(kInvalid, "expected a variant of " + enumType.name);
  }
  writer.varint(variant->ordinal);
  return true;
}

bool writeDecimal(const ValueShape& shape, const Json& value, Context& context, Writer& writer) {
  std::optional<std::string> canonical;
  if (value.is_string()) {
    canonical = canonicalDecimal(value.get_ref<const std::string&>(), shape.precision, shape.scale);
  }
  if (!canonical.has_value()) {
    return context.fail(kInvalid, "expected a decimal string with at most " + std::to_string(shape.scale) +
                                      " fraction digits and " + std::to_string(shape.precision) + " digits");
  }
  writer.lengthDelimited(viewOf(*canonical));
  return true;
}

bool writeNested(const ModelDescriptor& model, const Json& value, ByteView previousBody, Context& context,
                 Writer& writer) {
  EncodeOptions options;
  options.previous = previousBody;
  Bytes body;
  if (!encodeModel(model, value, options, context, body)) {
    return false;
  }
  writer.lengthDelimited(body);
  return true;
}

const OneofVariantDescriptor* findVariant(const ValueShape& shape, const std::string& name) {
  for (const OneofVariantDescriptor& variant : shape.variants) {
    if (variant.name == name) {
      return &variant;
    }
  }
  return nullptr;
}

bool writeOneof(const ValueShape& shape, const Json& value, Context& context, Writer& writer) {
  if (!value.is_object() || value.size() != 1) {
    return context.fail(kInvalid, "expected an object with exactly one variant");
  }
  const std::string& name = value.begin().key();
  const OneofVariantDescriptor* variant = findVariant(shape, name);
  if (variant == nullptr) {
    return context.fail(kInvalid, "unknown variant " + name);
  }
  PathSegment segment(context, fieldSegment(name));
  Writer body;
  body.key(variant->ordinal, wireTypeOf(variant->value));
  if (!writeValue(variant->value, noConstraints(), value.begin().value(), ByteView(), context, body)) {
    return false;
  }
  writer.lengthDelimited(body.bytes());
  return true;
}

bool writeValue(const ValueShape& shape, const ValueConstraints& constraints, const Json& value, ByteView previousBody,
                Context& context, Writer& writer) {
  switch (shape.kind) {
    case ValueKind::Scalar:
      return writeScalar(shape.scalar, constraints, value, context, writer);
    case ValueKind::Enum:
      return writeEnum(*shape.enumType, value, context, writer);
    case ValueKind::Decimal:
      return writeDecimal(shape, value, context, writer);
    case ValueKind::Message:
    case ValueKind::File:
      return writeNested(*shape.model, value, previousBody, context, writer);
    case ValueKind::Oneof:
      return writeOneof(shape, value, context, writer);
  }
  return false;
}

// ── Lists and maps ────────────────────────────────────────────────────────────

// Each element's value with no key, or with `elementTag` before it when it is set.
bool writeElements(const FieldDescriptor& field, const Json& array, std::optional<uint32_t> elementTag,
                   Context& context, Writer& writer) {
  for (size_t index = 0; index < array.size(); ++index) {
    PathSegment segment(context, indexSegment(index));
    if (elementTag.has_value()) {
      writer.key(*elementTag, wireTypeOf(field.value));
    }
    if (!writeValue(field.value, field.constraints, array[index], ByteView(), context, writer)) {
      return false;
    }
  }
  return true;
}

bool writeList(const FieldDescriptor& field, const Json& array, uint32_t tag, bool packed, Context& context,
               Writer& writer) {
  if (!array.is_array()) {
    return context.fail(kInvalid, "expected an array");
  }
  if (!packed) {
    return writeElements(field, array, tag, context, writer);
  }
  Writer packedBody;
  if (!writeElements(field, array, std::nullopt, context, packedBody)) {
    return false;
  }
  if (!array.empty()) {
    writer.key(tag, WireType::Len);
    writer.lengthDelimited(packedBody.bytes());
  }
  return true;
}

std::optional<uint64_t> parseIntegerKey(Scalar scalar, const std::string& text) {
  std::optional<IntegerRange> range = narrowIntegerRange(scalar);
  bool isSigned = scalar == Scalar::I64 || (range.has_value() && range->isSigned);
  if (!isSigned) {
    std::optional<uint64_t> number = parseUnsignedDecimalText(text);
    if (!number.has_value() || (range.has_value() && *number > range->maximum)) {
      return std::nullopt;
    }
    return number;
  }
  std::optional<int64_t> number = parseSignedDecimalText(text);
  bool inRange = number.has_value() && (!range.has_value() || (*number >= range->minimum && *number <= static_cast<int64_t>(range->maximum)));
  if (!inRange) {
    return std::nullopt;
  }
  return static_cast<uint64_t>(*number);
}

// Writes the key's value and returns the bytes map entries are sorted by.
std::optional<Bytes> writeMapKey(Scalar scalar, const std::string& text, Writer& writer) {
  std::optional<Bytes> keyBytes;
  if (scalar == Scalar::String) {
    keyBytes = bytesOf(text);
  }
  if (scalar == Scalar::Uuid) {
    keyBytes = uuidTextToBytes(text);
  }
  if (keyBytes.has_value()) {
    writer.lengthDelimited(*keyBytes);
    return keyBytes;
  }
  std::optional<uint64_t> number;
  if (scalar == Scalar::Bool && (text == "true" || text == "false")) {
    number = static_cast<uint64_t>(text == "true");
  }
  if (scalar != Scalar::Bool && scalar != Scalar::String && scalar != Scalar::Uuid) {
    number = parseIntegerKey(scalar, text);
  }
  if (!number.has_value()) {
    return std::nullopt;
  }
  writer.varint(*number);
  return wire::varintBytes(*number);
}

struct MapEntry {
  Bytes keyBytes;
  Bytes body;
};

bool writeMapEntry(const FieldDescriptor& field, const std::string& key, const Json& value, Context& context,
                   std::vector<MapEntry>& entries) {
  PathSegment segment(context, keySegment(key));
  Writer entry;
  entry.key(1, wireTypeOfScalar(field.container.mapKey));
  std::optional<Bytes> keyBytes = writeMapKey(field.container.mapKey, key, entry);
  if (!keyBytes.has_value()) {
    return context.fail(kInvalid, "map key does not fit the key type");
  }
  entry.key(2, wireTypeOf(field.value));
  if (!writeValue(field.value, field.constraints, value, ByteView(), context, entry)) {
    return false;
  }
  entries.push_back(MapEntry{std::move(*keyBytes), entry.take()});
  return true;
}

bool writeMap(const FieldDescriptor& field, const Json& object, uint32_t tag, Context& context, Writer& writer) {
  if (!object.is_object()) {
    return context.fail(kInvalid, "expected an object");
  }
  std::vector<MapEntry> entries;
  for (const auto& item : object.items()) {
    if (!writeMapEntry(field, item.key(), item.value(), context, entries)) {
      return false;
    }
  }
  std::sort(entries.begin(), entries.end(),
            [](const MapEntry& left, const MapEntry& right) { return left.keyBytes < right.keyBytes; });
  auto duplicate = std::adjacent_find(entries.begin(), entries.end(), [](const MapEntry& left, const MapEntry& right) {
    return left.keyBytes == right.keyBytes;
  });
  if (duplicate != entries.end()) {
    return context.fail(kInvalid, "two map keys name the same key");
  }
  for (const MapEntry& entry : entries) {
    writer.key(tag, WireType::Len);
    writer.lengthDelimited(entry.body);
  }
  return true;
}

// ── Fields ────────────────────────────────────────────────────────────────────

bool writeWrapped(const FieldDescriptor& field, const Json& value, Context& context, Writer& writer) {
  Writer wrapper;
  bool written = false;
  if (field.container.kind == ContainerKind::WrapperRepeated) {
    written = writeList(field, value, 1, field.container.packed, context, wrapper);
  } else {
    written = writeMap(field, value, 1, context, wrapper);
  }
  if (!written) {
    return false;
  }
  writer.key(field.ordinal, WireType::Len);
  writer.lengthDelimited(wrapper.bytes());
  return true;
}

bool writeField(const FieldDescriptor& field, const Json& value, ByteView previousBody, Context& context,
                Writer& writer) {
  switch (field.container.kind) {
    case ContainerKind::Singular:
      writer.key(field.ordinal, wireTypeOf(field.value));
      return writeValue(field.value, field.constraints, value, previousBody, context, writer);
    case ContainerKind::RepeatedPacked:
      return writeList(field, value, field.ordinal, true, context, writer);
    case ContainerKind::RepeatedLen:
      return writeList(field, value, field.ordinal, false, context, writer);
    case ContainerKind::Map:
      return writeMap(field, value, field.ordinal, context, writer);
    default:
      return writeWrapped(field, value, context, writer);
  }
}

bool indexPrevious(ByteView bytes, PreviousFields& previous) {
  wire::Reader reader(bytes);
  while (!reader.atEnd()) {
    wire::Field field;
    if (reader.next(field) != Status::Ok) {
      return false;
    }
    previous[field.ordinal].push_back(field);
  }
  return true;
}

// The last previous value of a singular message field, so its unknown fields survive.
ByteView previousMessageBody(const FieldDescriptor& field, const PreviousFields& previous) {
  auto found = previous.find(field.ordinal);
  bool isMessage = field.value.kind == ValueKind::Message || field.value.kind == ValueKind::File;
  bool singularMessage = field.container.kind == ContainerKind::Singular && isMessage;
  if (!singularMessage || found == previous.end() || found->second.back().type != WireType::Len) {
    return ByteView();
  }
  return found->second.back().body;
}

bool keepPrevious(const FieldDescriptor& field, const PreviousFields& previous, Context& context,
                  std::vector<Chunk>& chunks) {
  auto found = previous.find(field.ordinal);
  if (found == previous.end()) {
    if (field.required) {
      return context.fail(kInvalid, "is required");
    }
    return true;
  }
  for (const wire::Field& occurrence : found->second) {
    chunks.push_back(Chunk{field.ordinal, Bytes(occurrence.raw.begin(), occurrence.raw.end())});
  }
  return true;
}

// JSON null means "absent", except as the value of a required json field.
bool meansAbsent(const FieldDescriptor& field, const Json& value) {
  bool requiredJson = field.required && field.value.kind == ValueKind::Scalar && field.value.scalar == Scalar::JsonValue;
  return value.is_null() && !requiredJson;
}

bool encodeModelField(const FieldDescriptor& field, const Json& object, const PreviousFields& previous,
                      const EncodeOptions& options, Context& context, std::vector<Chunk>& chunks) {
  PathSegment segment(context, fieldSegment(field.name));
  auto found = object.find(field.name);
  if (found == object.end() && options.keepMissing) {
    return keepPrevious(field, previous, context, chunks);
  }
  if (found == object.end() || meansAbsent(field, *found)) {
    if (field.required) {
      return context.fail(kInvalid, "is required");
    }
    return true;
  }
  Writer writer;
  if (!writeField(field, *found, previousMessageBody(field, previous), context, writer)) {
    return false;
  }
  chunks.push_back(Chunk{field.ordinal, writer.take()});
  return true;
}

bool rejectUnknownNames(const ModelDescriptor& model, const Json& object, Context& context) {
  for (const auto& item : object.items()) {
    if (model.fieldByName(item.key()) == nullptr) {
      PathSegment segment(context, fieldSegment(item.key()));
      return context.fail(kInvalid, "is not a field of " + model.name);
    }
  }
  return true;
}

void carryUnknownFields(const ModelDescriptor& model, const PreviousFields& previous, std::vector<Chunk>& chunks) {
  for (const auto& [ordinal, occurrences] : previous) {
    if (model.fieldByOrdinal(ordinal) != nullptr) {
      continue;
    }
    for (const wire::Field& occurrence : occurrences) {
      chunks.push_back(Chunk{ordinal, Bytes(occurrence.raw.begin(), occurrence.raw.end())});
    }
  }
}

bool isSelected(const EncodeOptions& options, uint32_t ordinal) {
  return options.fields == nullptr || options.fields->count(ordinal) != 0;
}

bool encodeModel(const ModelDescriptor& model, const Json& object, const EncodeOptions& options, Context& context,
                 Bytes& out) {
  if (!object.is_object()) {
    return context.fail(kInvalid, "expected an object");
  }
  PreviousFields previous;
  if (!indexPrevious(options.previous, previous)) {
    return context.fail(Status::Malformed, "the previous encoding is malformed");
  }
  if (!context.enter() || !rejectUnknownNames(model, object, context)) {
    return false;
  }
  std::vector<Chunk> chunks;
  for (const FieldDescriptor& field : model.fields) {
    if (isSelected(options, field.ordinal) && !encodeModelField(field, object, previous, options, context, chunks)) {
      return false;
    }
  }
  carryUnknownFields(model, previous, chunks);
  std::stable_sort(chunks.begin(), chunks.end(),
                   [](const Chunk& left, const Chunk& right) { return left.ordinal < right.ordinal; });
  for (const Chunk& chunk : chunks) {
    appendTo(out, chunk.bytes);
  }
  context.leave();
  return true;
}

}  // namespace

}  // namespace codec

Result<Bytes> encodeMessage(const ModelDescriptor& model, const Json& object, const EncodeOptions& options,
                            CodecError& error) {
  error = CodecError{};
  codec::Context context(error, model.name);
  Bytes out;
  if (!codec::encodeModel(model, object, options, context, out)) {
    return error.status;
  }
  return out;
}

}  // namespace nw
