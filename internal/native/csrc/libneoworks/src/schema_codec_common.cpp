#include <cstdint>
#include <limits>

#include "schema_codec_internal.hpp"
#include "schema_values.hpp"

namespace nw::codec {

namespace {

bool checkNumber(const ValueConstraints& constraints, double number) {
  bool aboveMinimum = !constraints.minValue.has_value() || number >= *constraints.minValue;
  bool belowMaximum = !constraints.maxValue.has_value() || number <= *constraints.maxValue;
  return aboveMinimum && belowMaximum;
}

bool checkLength(const ValueConstraints& constraints, uint64_t length) {
  bool longEnough = !constraints.minLength.has_value() || length >= *constraints.minLength;
  bool shortEnough = !constraints.maxLength.has_value() || length <= *constraints.maxLength;
  return longEnough && shortEnough;
}

bool matchesPattern(const ValueConstraints& constraints, const std::string& text) {
  if (constraints.compiledPattern == nullptr) {
    return true;
  }
  std::optional<std::wstring> wide = utf8ToWide(text);
  return wide.has_value() && std::regex_match(*wide, *constraints.compiledPattern);
}

bool checkText(const ValueConstraints& constraints, const std::string& text, Context& context, Status status) {
  std::optional<size_t> codePoints = countCodePoints(text);
  if (!codePoints.has_value()) {
    return context.fail(status, "string is not valid UTF-8");
  }
  if (!checkLength(constraints, *codePoints)) {
    return context.fail(status, "length " + std::to_string(*codePoints) + " is outside the allowed range");
  }
  if (!matchesPattern(constraints, text)) {
    return context.fail(status, "does not match the pattern " + constraints.pattern.value_or(""));
  }
  if (constraints.format.has_value() && !matchesFormat(*constraints.format, text)) {
    return context.fail(status, "is not a valid " + *constraints.format);
  }
  return true;
}

}  // namespace

bool Context::fail(Status status, std::string reason) {
  if (error_.status == Status::Ok) {
    error_.status = status;
    error_.path = path_;
    error_.reason = std::move(reason);
  }
  return false;
}

bool Context::enter() {
  if (depth_ >= kMaxMessageDepth) {
    return fail(Status::Malformed, "messages are nested too deeply");
  }
  ++depth_;
  return true;
}

PathSegment::PathSegment(Context& context, const std::string& segment)
    : context_(context), previousLength_(context.path().size()) {
  context_.path() += segment;
}

PathSegment::~PathSegment() { context_.path().resize(previousLength_); }

std::string fieldSegment(const std::string& name) { return "." + name; }

std::string indexSegment(size_t index) { return "[" + std::to_string(index) + "]"; }

std::string keySegment(const std::string& key) { return "[" + Json(key).dump() + "]"; }

wire::WireType wireTypeOfScalar(Scalar scalar) {
  switch (scalar) {
    case Scalar::F32:
    case Scalar::F64:
      return wire::WireType::I64;
    case Scalar::String:
    case Scalar::Binary:
    case Scalar::Uuid:
    case Scalar::JsonValue:
    case Scalar::Semver:
      return wire::WireType::Len;
    default:
      return wire::WireType::Varint;
  }
}

wire::WireType wireTypeOf(const ValueShape& value) {
  switch (value.kind) {
    case ValueKind::Scalar:
      return wireTypeOfScalar(value.scalar);
    case ValueKind::Enum:
      return wire::WireType::Varint;
    default:
      return wire::WireType::Len;
  }
}

bool checkConstraints(const ValueConstraints& constraints, const ConstrainedValue& value, Context& context,
                      Status status) {
  if (const double* number = std::get_if<double>(&value)) {
    if (!checkNumber(constraints, *number)) {
      return context.fail(status, "value is outside the allowed range");
    }
    return true;
  }
  if (const std::string* text = std::get_if<std::string>(&value)) {
    return checkText(constraints, *text, context, status);
  }
  if (const ByteView* bytes = std::get_if<ByteView>(&value)) {
    if (!checkLength(constraints, bytes->size())) {
      return context.fail(status, "length " + std::to_string(bytes->size()) + " is outside the allowed range");
    }
  }
  return true;
}

std::optional<IntegerRange> narrowIntegerRange(Scalar scalar) {
  switch (scalar) {
    case Scalar::I8:
      return IntegerRange{true, INT8_MIN, INT8_MAX};
    case Scalar::I16:
      return IntegerRange{true, INT16_MIN, INT16_MAX};
    case Scalar::I32:
      return IntegerRange{true, INT32_MIN, INT32_MAX};
    case Scalar::U8:
      return IntegerRange{false, 0, UINT8_MAX};
    case Scalar::U16:
      return IntegerRange{false, 0, UINT16_MAX};
    case Scalar::U32:
      return IntegerRange{false, 0, UINT32_MAX};
    default:
      return std::nullopt;
  }
}

bool isWideInteger(Scalar scalar) {
  return scalar == Scalar::I64 || scalar == Scalar::U64 || scalar == Scalar::Duration;
}

}  // namespace nw::codec
