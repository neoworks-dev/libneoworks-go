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
// and Neoworks tables as data. Field references inside `tables` are ordinals.
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
  Semver,
};

// File is the built-in file type: it is encoded and decoded as the message `fileModel()`.
// Reference is a `ref<Table>`: the message `referenceModel()`.
enum class ValueKind { Scalar, Enum, Message, Decimal, Oneof, File, Reference };

struct EnumDescriptor;
struct ModelDescriptor;
struct OneofVariantDescriptor;

struct ValueShape {
  ValueKind kind = ValueKind::Scalar;
  Scalar scalar = Scalar::Bool;
  // Enum or model name, resolved into enumType / model after parsing. A File has `fileModel()`,
  // a Reference `referenceModel()`.
  std::string name;
  const EnumDescriptor* enumType = nullptr;
  const ModelDescriptor* model = nullptr;
  uint32_t precision = 0;
  uint32_t scale = 0;
  // The qualified name of the table a Reference names; empty for any other value.
  std::string reference;
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

// A sorted index over single field values, leading field first. It lives on the device only.
struct IndexDescriptor {
  std::vector<uint32_t> fields;
};

// A model stored as rows. `title` names a string or File field; a File is titled by its name.
// `belongsTo` names the single Reference whose row this row's key is wrapped under, and `cascade`
// the References whose row's deletion deletes this one. `indexes` name single fields that can be
// filtered, see query_fields.hpp.
struct TableDescriptor {
  std::string modelName;
  const ModelDescriptor* model = nullptr;
  std::vector<FacetDescriptor> facets;
  std::optional<uint32_t> title;
  std::optional<uint32_t> belongsTo;
  std::vector<uint32_t> cascade;
  std::vector<IndexDescriptor> indexes;

  const FacetDescriptor* facetOfField(uint32_t ordinal) const;
  const FacetDescriptor* facetByTag(uint32_t tag) const;
  bool cascades(uint32_t ordinal) const;
};

struct SchemaDescriptor {
  uint32_t descriptorVersion = 0;
  std::string namespaceName;
  std::vector<EnumDescriptor> enums;
  std::vector<ModelDescriptor> models;
  std::vector<TableDescriptor> tables;

  const ModelDescriptor* modelByName(std::string_view modelName) const;
  const EnumDescriptor* enumByName(std::string_view enumName) const;
  const TableDescriptor* tableByName(std::string_view modelName) const;
};

// The message a File value is: {objectId: uuid, name: string, mediaType: string, size: u64,
// variants: {string: FileVariant}, key: 32 bytes} with the ordinals 1 to 6, and FileVariant
// {objectId, size}. The key encrypts the file's objects and never leaves the core.
const ModelDescriptor& fileModel();
constexpr uint32_t kFileNameOrdinal = 2;
constexpr uint32_t kFileMediaTypeOrdinal = 3;
constexpr uint32_t kFileSizeOrdinal = 4;

// The message a reference is: {id: uuid, key: 32 bytes, absent on a @belongsTo field} with the
// ordinals 1 and 2. The key is the referenced row's key and never leaves the core.
const ModelDescriptor& referenceModel();

constexpr uint32_t kDescriptorVersion = 2;
constexpr uint32_t kDefaultFacetTag = 1;
constexpr const char* kDefaultFacetName = "default";

// A named facet's tag: 2 + (u32be(sha256("neoworks.facet:" || name)[0..4]) mod (kMaxOrdinal - 2)).
uint32_t facetTagForName(std::string_view facetName);

// Malformed for anything the openschema descriptor target would not emit: unknown keys or
// types, unresolved names, ordinals out of range or repeated, facets that do not cover each
// table field exactly once, tags that do not match their names, invalid patterns, a @belongsTo
// that is not a single reference to a table of the schema.
Result<std::shared_ptr<const SchemaDescriptor>> parseDescriptor(std::string_view text);

// A schema version of a collection whose descriptor a reader does not hold yet.
struct DescriptorNeed {
  std::string collection;
  std::string version;
};

}  // namespace nw
