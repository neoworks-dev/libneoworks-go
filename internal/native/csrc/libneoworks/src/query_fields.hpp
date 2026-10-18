#pragma once

#include <optional>
#include <string>

#include "descriptor.hpp"
#include "field_index.hpp"
#include "json.hpp"

namespace nw {

// How a value is compared. Message, oneof, json, binary and File values have no type here; a File
// is compared by its members, which have one.
enum class FieldType { Boolean, Integer, Real, Decimal, Text, Identifier, Enum, Timestamp, Date, Time, Duration };

// ASCII-only, as the insensitive mode compares.
std::string lowercaseAscii(std::string text);

// How the field's value, or each element of a list, is compared.
std::optional<FieldType> valueType(const FieldDescriptor& field);

// How a singular field is compared as a whole; nullopt for a list, map or File.
std::optional<FieldType> filterableType(const FieldDescriptor& field);

// A repeated field, which `some`, `every`, `none` and `has` filter over its elements.
bool isList(const FieldDescriptor& field);

// A map field, whose values `some`, `every`, `none` and `has` filter as a list's elements; its keys
// are not filterable.
bool isMap(const FieldDescriptor& field);

bool isFile(const FieldDescriptor& field);

// A field whose value is a message of the schema; a filter reaches the fields of the message, of its
// embedded messages and of its lists and maps.
bool isMessage(const FieldDescriptor& field);

// The members of a File that can be filtered and ordered: name, mediaType and size.
bool isFilterableFileMember(const FieldDescriptor& member);

// Whether lt, lte, gt, gte and ordering apply.
bool isOrdered(FieldType type);

// A value as the content JSON (contract amendment 7) writes it, or as a filter operand: 64-bit
// integers as numbers or decimal strings, timestamps as RFC 3339 strings, enums by name.
// Operands may also be a date-only timestamp or one with a numeric offset. nullopt when the
// JSON does not fit the field.
std::optional<Comparable> toComparable(const Json& value, const FieldDescriptor& field, FieldType type);

// The filterable values of a decoded content object of `model`, at any depth of embedded messages,
// lists and maps.
IndexedMessage indexedMessageOf(const ModelDescriptor& model, const Json& content);

}  // namespace nw
