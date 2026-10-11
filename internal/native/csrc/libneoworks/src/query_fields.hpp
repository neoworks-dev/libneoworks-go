#pragma once

#include <optional>
#include <string>

#include "descriptor.hpp"
#include "field_index.hpp"
#include "json.hpp"

namespace nw {

// How a field's values are compared. Repeated, map, message, oneof, json and binary fields have
// no type here: they cannot be filtered or ordered.
enum class FieldType { Boolean, Integer, Real, Decimal, Text, Identifier, Enum, Timestamp, Date, Time, Duration };

// ASCII-only, as `search` has always matched.
std::string lowercaseAscii(std::string text);

std::optional<FieldType> filterableType(const FieldDescriptor& field);

// Whether lt, lte, gt, gte and ordering apply.
bool isOrdered(FieldType type);

// A value as the content JSON (contract amendment 7) writes it, or as a filter operand: 64-bit
// integers as numbers or decimal strings, timestamps as RFC 3339 strings, enums by name.
// Operands may also be a date-only timestamp or one with a numeric offset. nullopt when the
// JSON does not fit the field.
std::optional<Comparable> toComparable(const Json& value, const FieldDescriptor& field, FieldType type);

// The filterable, set fields of a decoded content object of `model`.
FieldValues fieldValuesOf(const ModelDescriptor& model, const Json& content);

}  // namespace nw
