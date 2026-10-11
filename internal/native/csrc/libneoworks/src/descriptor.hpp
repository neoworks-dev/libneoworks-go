#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "status.hpp"

// An OpenSchema descriptor (openschema docs/descriptor.md): a schema's models, enums
// and Neoworks node layouts as data. Field references inside `nodes` are ordinals.
namespace nw {

enum class Scalar {
  Bool,
  I8,
  I16,
  I32,
  I64,
  U8,
  U16,
  U32,
  U64,
  F32,
  F64,
  String,
  Binary,
  Uuid,
  JsonValue,
  Date,
  Time,
  Timestamp,
  Duration,
};

enum class ValueKind { Scalar, Enum, Message, Decimal, Oneof };

struct EnumDescriptor;
struct ModelDescriptor;
struct OneofVariantDescriptor;

struct ValueShape {
  ValueKind kind = ValueKind::Scalar;
  Scalar scalar = Scalar::Bool;
  // Enum or model name, resolved into enumType / model after parsing.
  std::string name;
  const EnumDescriptor* enumType = nullptr;
  const ModelDescriptor* model = nullptr;
  uint32_t precision = 0;
  uint32_t scale = 0;
  std::vector<OneofVariantDescriptor> variants;
};

struct OneofVariantDescriptor {
  uint32_t ordinal = 0;
  std::string name;
  ValueShape value;
};

enum class ContainerKind { Singular, RepeatedPacked, RepeatedLen, WrapperRepeated, Map, WrapperMap };

struct ContainerShape {
  ContainerKind kind = ContainerKind::Singular;
  bool nullable = false;
  bool packed = false;
  Scalar mapKey = Scalar::String;
};

struct ValueConstraints {
  std::optional<double> minValue;
  std::optional<double> maxValue;
  std::optional<uint64_t> minLength;
  std::optional<uint64_t> maxLength;
  std::optional<std::string> pattern;
  std::shared_ptr<const std::wregex> compiledPattern;
  std::optional<std::string> format;
};

struct FieldDescriptor {
  uint32_t ordinal = 0;
  std::string name;
  ContainerShape container;
  ValueShape value;
  bool required = false;
  ValueConstraints constraints;
};

struct ModelDescriptor {
  std::string name;
  std::vector<FieldDescriptor> fields;

  const FieldDescriptor* fieldByOrdinal(uint32_t ordinal) const;
  const FieldDescriptor* fieldByName(std::string_view fieldName) const;
};

struct EnumVariantDescriptor {
  std::string name;
  uint32_t ordinal = 0;
};

struct EnumDescriptor {
  std::string name;
  std::vector<EnumVariantDescriptor> variants;

  const EnumVariantDescriptor* variantByOrdinal(uint64_t ordinal) const;
  const EnumVariantDescriptor* variantByName(std::string_view variantName) const;
};

struct FacetDescriptor {
  std::string name;
  uint32_t tag = 0;
  std::vector<uint32_t> fields;
};

struct TimeRangeDescriptor {
  uint32_t start = 0;
  uint32_t end = 0;
};

struct NodeDescriptor {
  std::string kind;
  std::string modelName;
  const ModelDescriptor* model = nullptr;
  std::vector<FacetDescriptor> facets;
  std::vector<uint32_t> searchable;
  std::optional<uint32_t> title;
  std::optional<TimeRangeDescriptor> timeRange;

  const FacetDescriptor* facetOfField(uint32_t ordinal) const;
  const FacetDescriptor* facetByTag(uint32_t tag) const;
};

struct SchemaDescriptor {
  uint32_t descriptorVersion = 0;
  std::string namespaceName;
  std::vector<EnumDescriptor> enums;
  std::vector<ModelDescriptor> models;
  std::vector<NodeDescriptor> nodes;

  const ModelDescriptor* modelByName(std::string_view modelName) const;
  const EnumDescriptor* enumByName(std::string_view enumName) const;
  const NodeDescriptor* nodeByKind(std::string_view kind) const;
};

constexpr uint32_t kDescriptorVersion = 1;
constexpr uint32_t kDefaultFacetTag = 1;
constexpr const char* kDefaultFacetName = "default";

// A named facet's tag: 2 + (u32be(sha256("neoworks.facet:" || name)[0..4]) mod (kMaxOrdinal - 2)).
uint32_t facetTagForName(std::string_view facetName);

// Malformed for anything the openschema descriptor target would not emit: unknown keys or
// types, unresolved names, ordinals out of range or repeated, facets that do not cover each
// node field exactly once, tags that do not match their names, invalid patterns.
Result<std::shared_ptr<const SchemaDescriptor>> parseDescriptor(std::string_view text);

}  // namespace nw
