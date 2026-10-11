#pragma once

#include <string>
#include <vector>

#include "descriptor.hpp"
#include "field_index.hpp"
#include "json.hpp"
#include "schema_codec.hpp"

// Prisma-style filters over indexed items: `{ where, orderBy, take }`. A query is validated
// against the schema once and then evaluated on indexed values without any decryption.
namespace nw {

enum class FilterOperator { Equals, Not, In, NotIn, Lt, Lte, Gt, Gte, Contains, StartsWith, EndsWith };

// One operator on one field. A null operand is nullopt.
struct FieldTest {
  uint32_t ordinal = 0;
  FilterOperator filterOperator = FilterOperator::Equals;
  std::vector<std::optional<Comparable>> operands;
  bool insensitive = false;
};

struct Condition {
  enum class Type {
    // Every child matches; no children matches everything.
    All,
    // Some child matches; no children matches nothing.
    Any,
    // The single child does not match.
    Not,
    Field,
    ParentId,
    // The single child matches the parent container's fields.
    ParentIs,
  };
  Type type = Type::All;
  std::vector<Condition> children;
  FieldTest test;
};

struct OrderKey {
  uint32_t ordinal = 0;
  bool descending = false;
};

struct Query {
  Condition where;
  std::vector<OrderKey> orderBy;
  std::optional<size_t> take;
};

// `item` is the model of the queried nodes, `container` the model `parent.is` filters on, null
// when the schema has none. InvalidArgument with the location in `error` for an unknown field or
// operator, a value or operator that does not fit the field's type, or any other malformed part.
Result<Query> compileQuery(const Json& json, const ModelDescriptor& item, const ModelDescriptor* container,
                           CodecError& error);

// The ids of the entries of `collection` that are items and match, in `query.orderBy` order and
// otherwise in id order.
std::vector<std::string> runQuery(const Query& query, const FieldIndex& index, const std::string& collection);

}  // namespace nw
