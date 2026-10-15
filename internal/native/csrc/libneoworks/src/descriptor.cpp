#include "descriptor.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <initializer_list>
#include <map>
#include <set>

#include "json.hpp"
#include "schema_values.hpp"
#include "wire.hpp"

namespace nw {

namespace {

const std::map<std::string, Scalar, std::less<>>& scalarNames() {
  static const std::map<std::string, Scalar, std::less<>> names = {
      {"bool", Scalar::Bool},     {"i8", Scalar::I8},          {"i16", Scalar::I16},
      {"i32", Scalar::I32},       {"i64", Scalar::I64},        {"u8", Scalar::U8},
      {"u16", Scalar::U16},       {"u32", Scalar::U32},        {"u64", Scalar::U64},
      {"f32", Scalar::F32},       {"f64", Scalar::F64},        {"string", Scalar::String},
      {"bytes", Scalar::Binary},   {"uuid", Scalar::Uuid},      {"json", Scalar::JsonValue},
      {"date", Scalar::Date},     {"time", Scalar::Time},      {"timestamp", Scalar::Timestamp},
      {"duration", Scalar::Duration},
  };
  return names;
}

FieldDescriptor builtInField(uint32_t ordinal, const char* name, Scalar scalar) {
  FieldDescriptor field;
  field.ordinal = ordinal;
  field.name = name;
  field.value.scalar = scalar;
  field.required = true;
  return field;
}

const ModelDescriptor& fileVariantModel() {
  static const ModelDescriptor model = [] {
    ModelDescriptor variant;
    variant.name = "FileVariant";
    variant.fields.push_back(builtInField(1, "objectId", Scalar::Uuid));
    variant.fields.push_back(builtInField(2, "size", Scalar::U64));
    return variant;
  }();
  return model;
}

FieldDescriptor builtInVariantsField() {
  FieldDescriptor field;
  field.ordinal = 5;
  field.name = "variants";
  field.container.kind = ContainerKind::Map;
  field.container.mapKey = Scalar::String;
  field.value.kind = ValueKind::Message;
  field.value.name = "FileVariant";
  field.value.model = &fileVariantModel();
  return field;
}

bool hasOnlyKeys(const Json& object, std::initializer_list<const char*> allowed) {
  if (!object.is_object()) {
    return false;
  }
  for (const auto& entry : object.items()) {
    bool known = std::any_of(allowed.begin(), allowed.end(), [&](const char* key) { return entry.key() == key; });
    if (!known) {
      return false;
    }
  }
  return true;
}

std::optional<uint32_t> readOrdinal(const Json& object, const char* key) {
  std::optional<uint64_t> value = readUnsigned(object, key);
  if (!value.has_value() || *value == 0 || *value > wire::kMaxOrdinal) {
    return std::nullopt;
  }
  return static_cast<uint32_t>(*value);
}

std::optional<Scalar> parseScalarName(const Json& object, const char* key) {
  std::optional<std::string> name = readString(object, key);
  if (!name.has_value()) {
    return std::nullopt;
  }
  auto found = scalarNames().find(*name);
  if (found == scalarNames().end()) {
    return std::nullopt;
  }
  return found->second;
}

bool isPackableScalar(Scalar scalar) {
  return scalar != Scalar::String && scalar != Scalar::Binary && scalar != Scalar::Uuid && scalar != Scalar::JsonValue;
}

bool isPackable(const ValueShape& value) {
  if (value.kind == ValueKind::Enum) {
    return true;
  }
  return value.kind == ValueKind::Scalar && isPackableScalar(value.scalar);
}

bool isMapKeyScalar(Scalar scalar) {
  switch (scalar) {
    case Scalar::String:
    case Scalar::Uuid:
    case Scalar::Bool:
    case Scalar::I8:
    case Scalar::I16:
    case Scalar::I32:
    case Scalar::I64:
    case Scalar::U8:
    case Scalar::U16:
    case Scalar::U32:
    case Scalar::U64:
      return true;
    default:
      return false;
  }
}

bool isNumericScalar(Scalar scalar) {
  switch (scalar) {
    case Scalar::I8:
    case Scalar::I16:
    case Scalar::I32:
    case Scalar::I64:
    case Scalar::U8:
    case Scalar::U16:
    case Scalar::U32:
    case Scalar::U64:
    case Scalar::F32:
    case Scalar::F64:
      return true;
    default:
      return false;
  }
}

bool isFacetName(std::string_view name) {
  if (name.empty() || !std::isalpha(static_cast<unsigned char>(name.front()))) {
    return false;
  }
  return std::all_of(name.begin(), name.end(), [](char character) {
    unsigned char byte = static_cast<unsigned char>(character);
    return byte < 0x80 && std::isalnum(byte);
  });
}

bool equalsIgnoringCase(std::string_view left, std::string_view right) {
  if (left.size() != right.size()) {
    return false;
  }
  for (size_t index = 0; index < left.size(); ++index) {
    if (std::tolower(static_cast<unsigned char>(left[index])) != std::tolower(static_cast<unsigned char>(right[index]))) {
      return false;
    }
  }
  return true;
}

std::optional<std::vector<uint32_t>> readOrdinalList(const Json& object, const char* key) {
  const Json* array = readArray(object, key);
  if (array == nullptr) {
    return std::nullopt;
  }
  std::vector<uint32_t> ordinals;
  for (const Json& entry : *array) {
    if (!entry.is_number_unsigned() || entry.get<uint64_t>() == 0 || entry.get<uint64_t>() > wire::kMaxOrdinal) {
      return std::nullopt;
    }
    ordinals.push_back(entry.get<uint32_t>());
  }
  return ordinals;
}

// ── Values and containers ─────────────────────────────────────────────────────

std::optional<ValueShape> parseValue(const Json& json, size_t depth);

std::optional<OneofVariantDescriptor> parseVariant(const Json& json, size_t depth) {
  if (!hasOnlyKeys(json, {"ordinal", "name", "value"})) {
    return std::nullopt;
  }
  std::optional<uint32_t> ordinal = readOrdinal(json, "ordinal");
  std::optional<std::string> name = readString(json, "name");
  const Json* value = readObject(json, "value");
  if (!ordinal.has_value() || !name.has_value() || name->empty() || value == nullptr) {
    return std::nullopt;
  }
  std::optional<ValueShape> shape = parseValue(*value, depth + 1);
  if (!shape.has_value()) {
    return std::nullopt;
  }
  return OneofVariantDescriptor{*ordinal, *name, std::move(*shape)};
}

std::optional<ValueShape> parseOneof(const Json& json, size_t depth) {
  const Json* variants = readArray(json, "variants");
  if (!hasOnlyKeys(json, {"kind", "variants"}) || variants == nullptr || variants->empty()) {
    return std::nullopt;
  }
  ValueShape shape;
  shape.kind = ValueKind::Oneof;
  std::set<uint32_t> ordinals;
  std::set<std::string> names;
  for (const Json& entry : *variants) {
    std::optional<OneofVariantDescriptor> variant = parseVariant(entry, depth);
    if (!variant.has_value() || !ordinals.insert(variant->ordinal).second || !names.insert(variant->name).second) {
      return std::nullopt;
    }
    shape.variants.push_back(std::move(*variant));
  }
  return shape;
}

std::optional<ValueShape> parseDecimal(const Json& json) {
  std::optional<uint64_t> precision = readUnsigned(json, "precision");
  std::optional<uint64_t> scale = readUnsigned(json, "scale");
  if (!hasOnlyKeys(json, {"kind", "precision", "scale"}) || !precision.has_value() || !scale.has_value()) {
    return std::nullopt;
  }
  if (*precision == 0 || *precision > 1000 || *scale > *precision) {
    return std::nullopt;
  }
  ValueShape shape;
  shape.kind = ValueKind::Decimal;
  shape.precision = static_cast<uint32_t>(*precision);
  shape.scale = static_cast<uint32_t>(*scale);
  return shape;
}

std::optional<ValueShape> parseFile(const Json& json) {
  if (!hasOnlyKeys(json, {"kind"})) {
    return std::nullopt;
  }
  ValueShape shape;
  shape.kind = ValueKind::File;
  shape.name = fileModel().name;
  shape.model = &fileModel();
  return shape;
}

std::optional<ValueShape> parseNamed(const Json& json, ValueKind kind) {
  std::optional<std::string> name = readString(json, "name");
  if (!hasOnlyKeys(json, {"kind", "name"}) || !name.has_value()) {
    return std::nullopt;
  }
  ValueShape shape;
  shape.kind = kind;
  shape.name = *name;
  return shape;
}

std::optional<ValueShape> parseValue(const Json& json, size_t depth) {
  std::optional<std::string> kind = readString(json, "kind");
  if (!kind.has_value() || depth > kMaxJsonDepth) {
    return std::nullopt;
  }
  if (*kind == "scalar") {
    std::optional<Scalar> scalar = parseScalarName(json, "scalar");
    std::optional<std::string> reference = readString(json, "reference");
    bool referenceFits = !json.contains("reference") || (reference.has_value() && !reference->empty() && scalar == Scalar::Uuid);
    if (!hasOnlyKeys(json, {"kind", "scalar", "reference"}) || !scalar.has_value() || !referenceFits) {
      return std::nullopt;
    }
    ValueShape shape;
    shape.scalar = *scalar;
    if (reference.has_value()) {
      shape.reference = *reference;
    }
    return shape;
  }
  if (*kind == "enum") {
    return parseNamed(json, ValueKind::Enum);
  }
  if (*kind == "message") {
    return parseNamed(json, ValueKind::Message);
  }
  if (*kind == "decimal") {
    return parseDecimal(json);
  }
  if (*kind == "file") {
    return parseFile(json);
  }
  if (*kind == "oneof") {
    return parseOneof(json, depth);
  }
  return std::nullopt;
}

std::optional<ContainerShape> parseFlaggedContainer(const Json& json, ContainerKind kind, const char* flag) {
  std::optional<bool> value = readBool(json, flag);
  if (!hasOnlyKeys(json, {"kind", flag}) || !value.has_value()) {
    return std::nullopt;
  }
  ContainerShape shape;
  shape.kind = kind;
  if (kind == ContainerKind::Singular) {
    shape.nullable = *value;
  }
  if (kind == ContainerKind::WrapperRepeated) {
    shape.packed = *value;
  }
  return shape;
}

std::optional<ContainerShape> parseMapContainer(const Json& json, ContainerKind kind) {
  std::optional<Scalar> key = parseScalarName(json, "key");
  if (!hasOnlyKeys(json, {"kind", "key"}) || !key.has_value() || !isMapKeyScalar(*key)) {
    return std::nullopt;
  }
  ContainerShape shape;
  shape.kind = kind;
  shape.mapKey = *key;
  return shape;
}

std::optional<ContainerShape> parseContainer(const Json& json) {
  std::optional<std::string> kind = readString(json, "kind");
  if (!kind.has_value()) {
    return std::nullopt;
  }
  ContainerShape shape;
  if (*kind == "singular") {
    return parseFlaggedContainer(json, ContainerKind::Singular, "nullable");
  }
  if (*kind == "wrapperRepeated") {
    return parseFlaggedContainer(json, ContainerKind::WrapperRepeated, "packed");
  }
  if (*kind == "map") {
    return parseMapContainer(json, ContainerKind::Map);
  }
  if (*kind == "wrapperMap") {
    return parseMapContainer(json, ContainerKind::WrapperMap);
  }
  if (*kind != "repeatedPacked" && *kind != "repeatedLen") {
    return std::nullopt;
  }
  if (!hasOnlyKeys(json, {"kind"})) {
    return std::nullopt;
  }
  shape.kind = ContainerKind::RepeatedLen;
  if (*kind == "repeatedPacked") {
    shape.kind = ContainerKind::RepeatedPacked;
  }
  return shape;
}

// ── Constraints ───────────────────────────────────────────────────────────────

bool readOptionalNumber(const Json& object, const char* key, std::optional<double>& into) {
  if (!object.contains(key)) {
    return true;
  }
  const Json& value = object.at(key);
  if (!value.is_number() || !std::isfinite(value.get<double>())) {
    return false;
  }
  into = value.get<double>();
  return true;
}

bool readOptionalLength(const Json& object, const char* key, std::optional<uint64_t>& into) {
  if (!object.contains(key)) {
    return true;
  }
  if (!object.at(key).is_number_unsigned()) {
    return false;
  }
  into = object.at(key).get<uint64_t>();
  return true;
}

bool readOptionalText(const Json& object, const char* key, std::optional<std::string>& into) {
  if (!object.contains(key)) {
    return true;
  }
  if (!object.at(key).is_string()) {
    return false;
  }
  into = object.at(key).get<std::string>();
  return true;
}

bool compilePattern(ValueConstraints& constraints) {
  if (!constraints.pattern.has_value()) {
    return true;
  }
  std::optional<std::wstring> wide = utf8ToWide(*constraints.pattern);
  if (!wide.has_value()) {
    return false;
  }
  try {
    constraints.compiledPattern = std::make_shared<const std::wregex>(*wide, std::regex::ECMAScript);
  } catch (const std::regex_error&) {
    return false;
  }
  return true;
}

std::optional<ValueConstraints> parseConstraints(const Json& json) {
  if (!hasOnlyKeys(json, {"minValue", "maxValue", "minLength", "maxLength", "pattern", "format"})) {
    return std::nullopt;
  }
  ValueConstraints constraints;
  bool wellFormed = readOptionalNumber(json, "minValue", constraints.minValue) &&
                    readOptionalNumber(json, "maxValue", constraints.maxValue) &&
                    readOptionalLength(json, "minLength", constraints.minLength) &&
                    readOptionalLength(json, "maxLength", constraints.maxLength) &&
                    readOptionalText(json, "pattern", constraints.pattern) &&
                    readOptionalText(json, "format", constraints.format) && compilePattern(constraints);
  if (!wellFormed) {
    return std::nullopt;
  }
  return constraints;
}

bool constraintsFitValue(const ValueConstraints& constraints, const ValueShape& value) {
  bool isScalar = value.kind == ValueKind::Scalar;
  bool numeric = isScalar && isNumericScalar(value.scalar);
  bool text = isScalar && value.scalar == Scalar::String;
  bool measurable = text || (isScalar && value.scalar == Scalar::Binary);
  bool hasValueBound = constraints.minValue.has_value() || constraints.maxValue.has_value();
  bool hasLengthBound = constraints.minLength.has_value() || constraints.maxLength.has_value();
  bool hasTextRule = constraints.pattern.has_value() || constraints.format.has_value();
  return (!hasValueBound || numeric) && (!hasLengthBound || measurable) && (!hasTextRule || text);
}

// ── Fields, models, enums ─────────────────────────────────────────────────────

bool containerFitsValue(const ContainerShape& container, const ValueShape& value) {
  switch (container.kind) {
    case ContainerKind::RepeatedPacked:
      return isPackable(value);
    case ContainerKind::RepeatedLen:
      return !isPackable(value);
    case ContainerKind::WrapperRepeated:
      return container.packed == isPackable(value);
    default:
      return true;
  }
}

std::optional<FieldDescriptor> parseField(const Json& json) {
  if (!hasOnlyKeys(json, {"ordinal", "name", "container", "value", "required", "constraints"})) {
    return std::nullopt;
  }
  std::optional<uint32_t> ordinal = readOrdinal(json, "ordinal");
  std::optional<std::string> name = readString(json, "name");
  std::optional<bool> required = readBool(json, "required");
  const Json* container = readObject(json, "container");
  const Json* value = readObject(json, "value");
  const Json* constraints = readObject(json, "constraints");
  if (!ordinal.has_value() || !name.has_value() || name->empty() || !required.has_value() || container == nullptr ||
      value == nullptr || constraints == nullptr) {
    return std::nullopt;
  }
  FieldDescriptor field;
  field.ordinal = *ordinal;
  field.name = *name;
  field.required = *required;
  std::optional<ContainerShape> containerShape = parseContainer(*container);
  std::optional<ValueShape> valueShape = parseValue(*value, 0);
  std::optional<ValueConstraints> valueConstraints = parseConstraints(*constraints);
  if (!containerShape.has_value() || !valueShape.has_value() || !valueConstraints.has_value()) {
    return std::nullopt;
  }
  field.container = *containerShape;
  field.value = std::move(*valueShape);
  field.constraints = std::move(*valueConstraints);
  bool requiredMatches = field.required == (field.container.kind == ContainerKind::Singular && !field.container.nullable);
  if (!requiredMatches || !containerFitsValue(field.container, field.value) ||
      !constraintsFitValue(field.constraints, field.value)) {
    return std::nullopt;
  }
  return field;
}

std::optional<ModelDescriptor> parseModel(const Json& json) {
  std::optional<std::string> name = readString(json, "name");
  const Json* fields = readArray(json, "fields");
  if (!hasOnlyKeys(json, {"name", "fields"}) || !name.has_value() || name->empty() || fields == nullptr) {
    return std::nullopt;
  }
  ModelDescriptor model;
  model.name = *name;
  std::set<uint32_t> ordinals;
  std::set<std::string> names;
  for (const Json& entry : *fields) {
    std::optional<FieldDescriptor> field = parseField(entry);
    if (!field.has_value() || !ordinals.insert(field->ordinal).second || !names.insert(field->name).second) {
      return std::nullopt;
    }
    model.fields.push_back(std::move(*field));
  }
  return model;
}

std::optional<EnumVariantDescriptor> parseEnumVariant(const Json& json) {
  std::optional<std::string> name = readString(json, "name");
  std::optional<uint64_t> ordinal = readUnsigned(json, "ordinal");
  if (!hasOnlyKeys(json, {"name", "ordinal"}) || !name.has_value() || name->empty() || !ordinal.has_value()) {
    return std::nullopt;
  }
  if (*ordinal > UINT32_MAX) {
    return std::nullopt;
  }
  return EnumVariantDescriptor{*name, static_cast<uint32_t>(*ordinal)};
}

std::optional<EnumDescriptor> parseEnum(const Json& json) {
  std::optional<std::string> name = readString(json, "name");
  const Json* variants = readArray(json, "variants");
  if (!hasOnlyKeys(json, {"name", "variants"}) || !name.has_value() || name->empty() || variants == nullptr) {
    return std::nullopt;
  }
  EnumDescriptor enumType;
  enumType.name = *name;
  std::set<uint32_t> ordinals;
  std::set<std::string> names;
  for (const Json& entry : *variants) {
    std::optional<EnumVariantDescriptor> variant = parseEnumVariant(entry);
    if (!variant.has_value() || !ordinals.insert(variant->ordinal).second || !names.insert(variant->name).second) {
      return std::nullopt;
    }
    enumType.variants.push_back(std::move(*variant));
  }
  return enumType;
}

// ── Nodes ─────────────────────────────────────────────────────────────────────

std::optional<FacetDescriptor> parseFacet(const Json& json) {
  std::optional<std::string> name = readString(json, "name");
  std::optional<uint32_t> tag = readOrdinal(json, "tag");
  std::optional<std::vector<uint32_t>> fields = readOrdinalList(json, "fields");
  if (!hasOnlyKeys(json, {"name", "tag", "fields"}) || !name.has_value() || !tag.has_value() || !fields.has_value()) {
    return std::nullopt;
  }
  bool isDefault = *name == kDefaultFacetName;
  if (!isDefault && (!isFacetName(*name) || equalsIgnoringCase(*name, kDefaultFacetName))) {
    return std::nullopt;
  }
  uint32_t expectedTag = kDefaultFacetTag;
  if (!isDefault) {
    expectedTag = facetTagForName(*name);
  }
  if (*tag != expectedTag || fields->empty()) {
    return std::nullopt;
  }
  return FacetDescriptor{*name, *tag, std::move(*fields)};
}

std::optional<TimeRangeDescriptor> parseTimeRange(const Json& json) {
  std::optional<uint32_t> start = readOrdinal(json, "start");
  std::optional<uint32_t> end = readOrdinal(json, "end");
  if (!hasOnlyKeys(json, {"start", "end"}) || !start.has_value() || !end.has_value() || *start == *end) {
    return std::nullopt;
  }
  return TimeRangeDescriptor{*start, *end};
}

bool parseOptionalOrdinal(const Json& json, const char* key, std::optional<uint32_t>& into) {
  if (!json.contains(key)) {
    return false;
  }
  if (json.at(key).is_null()) {
    return true;
  }
  into = readOrdinal(json, key);
  return into.has_value();
}

bool parseOptionalTimeRange(const Json& json, std::optional<TimeRangeDescriptor>& into) {
  if (!json.contains("timeRange")) {
    return false;
  }
  if (json.at("timeRange").is_null()) {
    return true;
  }
  into = parseTimeRange(json.at("timeRange"));
  return into.has_value();
}

std::optional<NodeDescriptor> parseNode(const Json& json) {
  if (!hasOnlyKeys(json, {"kind", "model", "facets", "searchable", "title", "timeRange"})) {
    return std::nullopt;
  }
  NodeDescriptor node;
  std::optional<std::string> kind = readString(json, "kind");
  std::optional<std::string> model = readString(json, "model");
  std::optional<std::vector<uint32_t>> searchable = readOrdinalList(json, "searchable");
  const Json* facets = readArray(json, "facets");
  bool wellFormed = kind.has_value() && (*kind == "container" || *kind == "item") && model.has_value() &&
                    searchable.has_value() && facets != nullptr && parseOptionalOrdinal(json, "title", node.title) &&
                    parseOptionalTimeRange(json, node.timeRange);
  if (!wellFormed) {
    return std::nullopt;
  }
  node.kind = *kind;
  node.modelName = *model;
  node.searchable = std::move(*searchable);
  for (const Json& entry : *facets) {
    std::optional<FacetDescriptor> facet = parseFacet(entry);
    if (!facet.has_value()) {
      return std::nullopt;
    }
    node.facets.push_back(std::move(*facet));
  }
  return node;
}

// ── Resolution and cross-checks ───────────────────────────────────────────────

bool resolveValue(const SchemaDescriptor& schema, ValueShape& value) {
  if (value.kind == ValueKind::Enum) {
    value.enumType = schema.enumByName(value.name);
    return value.enumType != nullptr;
  }
  if (value.kind == ValueKind::Message) {
    value.model = schema.modelByName(value.name);
    return value.model != nullptr;
  }
  if (value.kind != ValueKind::Oneof) {
    return true;
  }
  return std::all_of(value.variants.begin(), value.variants.end(),
                     [&](OneofVariantDescriptor& variant) { return resolveValue(schema, variant.value); });
}

bool resolveModels(SchemaDescriptor& schema) {
  for (ModelDescriptor& model : schema.models) {
    bool resolved = std::all_of(model.fields.begin(), model.fields.end(),
                                [&](FieldDescriptor& field) { return resolveValue(schema, field.value); });
    if (!resolved) {
      return false;
    }
  }
  return true;
}

bool coverFacetFields(const NodeDescriptor& node, const FacetDescriptor& facet, std::set<uint32_t>& covered) {
  for (uint32_t ordinal : facet.fields) {
    if (node.model->fieldByOrdinal(ordinal) == nullptr || !covered.insert(ordinal).second) {
      return false;
    }
  }
  return true;
}

bool facetsPartitionModel(const NodeDescriptor& node) {
  std::set<uint32_t> covered;
  std::set<uint32_t> tags;
  for (const FacetDescriptor& facet : node.facets) {
    if (!tags.insert(facet.tag).second || !coverFacetFields(node, facet, covered)) {
      return false;
    }
  }
  return covered.size() == node.model->fields.size();
}

bool isTextValue(const ValueShape& value) {
  return value.kind == ValueKind::File || (value.kind == ValueKind::Scalar && value.scalar == Scalar::String);
}

// A string or a File, which is indexed by its name.
bool isTextField(const FieldDescriptor* field, bool allowLists) {
  if (field == nullptr || !isTextValue(field->value)) {
    return false;
  }
  ContainerKind kind = field->container.kind;
  bool list = kind == ContainerKind::RepeatedLen || kind == ContainerKind::WrapperRepeated;
  return kind == ContainerKind::Singular || (allowLists && list);
}

bool isSingularTimestamp(const FieldDescriptor* field) {
  return field != nullptr && field->container.kind == ContainerKind::Singular &&
         field->value.kind == ValueKind::Scalar && field->value.scalar == Scalar::Timestamp;
}

bool indexesFitModel(const NodeDescriptor& node) {
  const ModelDescriptor& model = *node.model;
  bool searchableFit = std::all_of(node.searchable.begin(), node.searchable.end(),
                                   [&](uint32_t ordinal) { return isTextField(model.fieldByOrdinal(ordinal), true); });
  bool titleFits = !node.title.has_value() || isTextField(model.fieldByOrdinal(*node.title), false);
  if (!node.timeRange.has_value()) {
    return searchableFit && titleFits;
  }
  const TimeRangeDescriptor& range = *node.timeRange;
  bool rangeFits = isSingularTimestamp(model.fieldByOrdinal(range.start)) &&
                   isSingularTimestamp(model.fieldByOrdinal(range.end)) &&
                   node.facetOfField(range.start) == node.facetOfField(range.end);
  return searchableFit && titleFits && rangeFits;
}

bool resolveNodes(SchemaDescriptor& schema) {
  std::set<std::string> kinds;
  for (NodeDescriptor& node : schema.nodes) {
    node.model = schema.modelByName(node.modelName);
    if (node.model == nullptr || !kinds.insert(node.kind).second) {
      return false;
    }
    if (!facetsPartitionModel(node) || !indexesFitModel(node)) {
      return false;
    }
  }
  return true;
}

template <typename Item>
bool namesAreUnique(const std::vector<Item>& items) {
  std::set<std::string> names;
  return std::all_of(items.begin(), items.end(), [&](const Item& item) { return names.insert(item.name).second; });
}

template <typename Item, typename Parse>
bool parseList(const Json& json, const char* key, std::vector<Item>& into, Parse parse) {
  const Json* array = readArray(json, key);
  if (array == nullptr) {
    return false;
  }
  for (const Json& entry : *array) {
    std::optional<Item> item = parse(entry);
    if (!item.has_value()) {
      return false;
    }
    into.push_back(std::move(*item));
  }
  return true;
}

}  // namespace

const ModelDescriptor& fileModel() {
  static const ModelDescriptor model = [] {
    ModelDescriptor file;
    file.name = "File";
    file.fields.push_back(builtInField(1, "objectId", Scalar::Uuid));
    file.fields.push_back(builtInField(2, "name", Scalar::String));
    file.fields.push_back(builtInField(3, "mediaType", Scalar::String));
    file.fields.push_back(builtInField(4, "size", Scalar::U64));
    file.fields.push_back(builtInVariantsField());
    return file;
  }();
  return model;
}

const FieldDescriptor* ModelDescriptor::fieldByOrdinal(uint32_t ordinal) const {
  for (const FieldDescriptor& field : fields) {
    if (field.ordinal == ordinal) {
      return &field;
    }
  }
  return nullptr;
}

const FieldDescriptor* ModelDescriptor::fieldByName(std::string_view fieldName) const {
  for (const FieldDescriptor& field : fields) {
    if (field.name == fieldName) {
      return &field;
    }
  }
  return nullptr;
}

const EnumVariantDescriptor* EnumDescriptor::variantByOrdinal(uint64_t ordinal) const {
  for (const EnumVariantDescriptor& variant : variants) {
    if (variant.ordinal == ordinal) {
      return &variant;
    }
  }
  return nullptr;
}

const EnumVariantDescriptor* EnumDescriptor::variantByName(std::string_view variantName) const {
  for (const EnumVariantDescriptor& variant : variants) {
    if (variant.name == variantName) {
      return &variant;
    }
  }
  return nullptr;
}

const FacetDescriptor* NodeDescriptor::facetOfField(uint32_t ordinal) const {
  for (const FacetDescriptor& facet : facets) {
    if (std::find(facet.fields.begin(), facet.fields.end(), ordinal) != facet.fields.end()) {
      return &facet;
    }
  }
  return nullptr;
}

const FacetDescriptor* NodeDescriptor::facetByTag(uint32_t tag) const {
  for (const FacetDescriptor& facet : facets) {
    if (facet.tag == tag) {
      return &facet;
    }
  }
  return nullptr;
}

const ModelDescriptor* SchemaDescriptor::modelByName(std::string_view modelName) const {
  for (const ModelDescriptor& model : models) {
    if (model.name == modelName) {
      return &model;
    }
  }
  return nullptr;
}

const EnumDescriptor* SchemaDescriptor::enumByName(std::string_view enumName) const {
  for (const EnumDescriptor& enumType : enums) {
    if (enumType.name == enumName) {
      return &enumType;
    }
  }
  return nullptr;
}

const NodeDescriptor* SchemaDescriptor::nodeByKind(std::string_view kind) const {
  for (const NodeDescriptor& node : nodes) {
    if (node.kind == kind) {
      return &node;
    }
  }
  return nullptr;
}

uint32_t facetTagForName(std::string_view facetName) {
  std::string input = "neoworks.facet:" + std::string(facetName);
  uint8_t digest[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(digest, reinterpret_cast<const uint8_t*>(input.data()), input.size());
  uint32_t prefix = (uint32_t{digest[0]} << 24) | (uint32_t{digest[1]} << 16) | (uint32_t{digest[2]} << 8) |
                    uint32_t{digest[3]};
  return 2 + prefix % (wire::kMaxOrdinal - 2);
}

Result<std::shared_ptr<const SchemaDescriptor>> parseDescriptor(std::string_view text) {
  std::optional<Json> json = parseJson(text);
  if (!json.has_value() || !hasOnlyKeys(*json, {"descriptorVersion", "namespace", "enums", "models", "nodes"})) {
    return Status::Malformed;
  }
  auto schema = std::make_shared<SchemaDescriptor>();
  std::optional<uint64_t> version = readUnsigned(*json, "descriptorVersion");
  std::optional<std::string> namespaceName = readString(*json, "namespace");
  if (!version.has_value() || *version != kDescriptorVersion || !namespaceName.has_value()) {
    return Status::Malformed;
  }
  schema->descriptorVersion = kDescriptorVersion;
  schema->namespaceName = *namespaceName;
  bool parsed = parseList(*json, "enums", schema->enums, parseEnum) &&
                parseList(*json, "models", schema->models, parseModel) &&
                parseList(*json, "nodes", schema->nodes, parseNode);
  if (!parsed || !namesAreUnique(schema->enums) || !namesAreUnique(schema->models)) {
    return Status::Malformed;
  }
  if (!resolveModels(*schema) || !resolveNodes(*schema)) {
    return Status::Malformed;
  }
  return std::shared_ptr<const SchemaDescriptor>(std::move(schema));
}

}  // namespace nw
