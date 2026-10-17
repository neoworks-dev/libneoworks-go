#pragma once

#include <string>
#include <vector>

#include "descriptor.hpp"
#include "field_index.hpp"
#include "json.hpp"
#include "schema_codec.hpp"

// Prisma-style filters over the indexed rows of one table: `{ where, orderBy, take, include }`. A
// File field is filtered and ordered by its members, `{ image: { name: { contains: "x" } } }`, and
// a list field by `some`, `every`, `none` and `has`. A query is validated against the table once
// and then evaluated on indexed values without any decryption.
namespace nw {

enum class FilterOperator { Equals, Not, In, NotIn, Lt, Lte, Gt, Gte, Contains, StartsWith, EndsWith };

// One operator on one field, or on one member of a File field. Inside a list quantifier the test
// looks at the element and `ordinal` is ignored. A null operand is nullopt.
struct FieldTest {
  uint32_t ordinal = 0;
  uint32_t member = kWholeValue;
  FilterOperator filterOperator = FilterOperator::Equals;
  std::vector<std::optional<Comparable>> operands;
  bool insensitive = false;
};

// How many elements of a list must match: at least one, all of them or none.
enum class Quantifier { Some, Every, None };

struct Condition {
  enum class Type {
    // Every child matches; no children matches everything.
    All,
    // Some child matches; no children matches nothing.
    Any,
    // The single child does not match.
    Not,
    Field,
    // The single child, tested against each element of the list field `listOrdinal`; an unset
    // list has no elements.
    Elements,
  };
  Type type = Type::All;
  std::vector<Condition> children;
  FieldTest test;
  Quantifier quantifier = Quantifier::Some;
  uint32_t listOrdinal = 0;
};

struct OrderKey {
  uint32_t ordinal = 0;
  uint32_t member = kWholeValue;
  bool descending = false;
};

// A single reference whose row is read along with each match.
struct IncludedField {
  uint32_t ordinal = 0;
  std::string name;
};

struct Query {
  Condition where;
  std::vector<OrderKey> orderBy;
  std::optional<size_t> take;
  std::vector<IncludedField> include;
};

// A matching row, and for each included field the row it refers to; nullopt when that row is not
// a live row this holder can read.
struct QueryRow {
  std::string id;
  std::vector<std::pair<std::string, std::optional<std::string>>> included;
};

// `model` is the queried table's model. InvalidArgument with the location in `error` for an
// unknown field or operator, a value or operator that does not fit the field's type, an include
// that is not a single reference, or any other malformed part.
Result<Query> compileQuery(const Json& json, const ModelDescriptor& model, CodecError& error);

// The rows of `table` in `collection` that match, in `query.orderBy` order and otherwise in id order.
std::vector<QueryRow> runQuery(const Query& query, const FieldIndex& index, const std::string& collection,
                               const std::string& table);

}  // namespace nw
