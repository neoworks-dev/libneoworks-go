#include <algorithm>

#include "query.hpp"
#include "query_fields.hpp"

namespace nw {

namespace {

// SQL's three-valued logic, as Prisma has it: comparing a missing value with anything but null
// is unknown, `NOT` keeps unknown unknown, and only true selects an item.
enum class Truth { False, True, Unknown };

Truth truthOf(bool holds) {
  if (holds) {
    return Truth::True;
  }
  return Truth::False;
}

Truth negated(Truth truth) {
  if (truth == Truth::Unknown) {
    return Truth::Unknown;
  }
  return truthOf(truth == Truth::False);
}

bool sameValue(const FieldTest& test, const Comparable* value, const std::optional<Comparable>& operand) {
  if (value == nullptr || !operand.has_value()) {
    return value == nullptr && !operand.has_value();
  }
  if (!test.insensitive || value->kind != Comparable::Kind::Text) {
    return compareValues(*value, *operand) == 0;
  }
  return lowercaseAscii(value->text) == operand->text;
}

bool equalsAny(const FieldTest& test, const Comparable* value) {
  for (const std::optional<Comparable>& operand : test.operands) {
    if (sameValue(test, value, operand)) {
      return true;
    }
  }
  return false;
}

bool orderingHolds(FilterOperator filterOperator, int comparison) {
  if (filterOperator == FilterOperator::Lt) {
    return comparison < 0;
  }
  if (filterOperator == FilterOperator::Lte) {
    return comparison <= 0;
  }
  if (filterOperator == FilterOperator::Gt) {
    return comparison > 0;
  }
  return comparison >= 0;
}

bool textHolds(FilterOperator filterOperator, const std::string& text, const std::string& part) {
  if (filterOperator == FilterOperator::Contains) {
    return text.find(part) != std::string::npos;
  }
  if (filterOperator == FilterOperator::StartsWith) {
    return text.size() >= part.size() && text.compare(0, part.size(), part) == 0;
  }
  return text.size() >= part.size() && text.compare(text.size() - part.size(), part.size(), part) == 0;
}

Comparable foldedForMode(const FieldTest& test, const Comparable& value) {
  Comparable folded = value;
  if (test.insensitive && value.kind == Comparable::Kind::Text) {
    folded.text = lowercaseAscii(value.text);
  }
  return folded;
}

bool matchesPresentValue(const FieldTest& test, const Comparable& value) {
  const Comparable& operand = *test.operands.front();
  Comparable folded = foldedForMode(test, value);
  if (test.filterOperator == FilterOperator::Contains || test.filterOperator == FilterOperator::StartsWith ||
      test.filterOperator == FilterOperator::EndsWith) {
    return textHolds(test.filterOperator, folded.text, operand.text);
  }
  return orderingHolds(test.filterOperator, compareValues(folded, operand));
}

bool isEquality(FilterOperator filterOperator) {
  return filterOperator == FilterOperator::Equals || filterOperator == FilterOperator::In;
}

bool isInequality(FilterOperator filterOperator) {
  return filterOperator == FilterOperator::Not || filterOperator == FilterOperator::NotIn;
}

bool hasNullOperand(const FieldTest& test) {
  return std::any_of(test.operands.begin(), test.operands.end(),
                     [](const std::optional<Comparable>& operand) { return !operand.has_value(); });
}

// A missing value is known only against a null operand: `equals: null` holds, `not: null` fails.
Truth missingValueTruth(const FieldTest& test) {
  if (!hasNullOperand(test)) {
    return Truth::Unknown;
  }
  if (isEquality(test.filterOperator)) {
    return Truth::True;
  }
  if (isInequality(test.filterOperator)) {
    return Truth::False;
  }
  return Truth::Unknown;
}

Truth testTruth(const FieldTest& test, const Comparable* value) {
  if (value == nullptr) {
    return missingValueTruth(test);
  }
  if (isEquality(test.filterOperator)) {
    return truthOf(equalsAny(test, value));
  }
  if (isInequality(test.filterOperator)) {
    return truthOf(!equalsAny(test, value));
  }
  return truthOf(matchesPresentValue(test, *value));
}

const Comparable* valueOf(const IndexedNode& node, uint32_t ordinal) {
  auto found = node.values.find(ordinal);
  if (found == node.values.end()) {
    return nullptr;
  }
  return &found->second;
}

Truth parentIdTruth(const FieldTest& test, const IndexedNode& node) {
  if (!node.parentId.has_value()) {
    return testTruth(test, nullptr);
  }
  Comparable parentId;
  parentId.kind = Comparable::Kind::Text;
  parentId.text = *node.parentId;
  return testTruth(test, &parentId);
}

Truth conditionTruth(const Condition& condition, const IndexedNode& node, const IndexedNode* parent);

Truth allTruth(const std::vector<Condition>& conditions, const IndexedNode& node, const IndexedNode* parent) {
  Truth combined = Truth::True;
  for (const Condition& child : conditions) {
    Truth truth = conditionTruth(child, node, parent);
    if (truth == Truth::False) {
      return Truth::False;
    }
    if (truth == Truth::Unknown) {
      combined = Truth::Unknown;
    }
  }
  return combined;
}

Truth anyTruth(const std::vector<Condition>& conditions, const IndexedNode& node, const IndexedNode* parent) {
  Truth combined = Truth::False;
  for (const Condition& child : conditions) {
    Truth truth = conditionTruth(child, node, parent);
    if (truth == Truth::True) {
      return Truth::True;
    }
    if (truth == Truth::Unknown) {
      combined = Truth::Unknown;
    }
  }
  return combined;
}

Truth parentIsTruth(const Condition& condition, const IndexedNode* parent) {
  if (parent == nullptr) {
    return Truth::False;
  }
  return conditionTruth(condition.children.front(), *parent, nullptr);
}

Truth conditionTruth(const Condition& condition, const IndexedNode& node, const IndexedNode* parent) {
  switch (condition.type) {
    case Condition::Type::All:
      return allTruth(condition.children, node, parent);
    case Condition::Type::Any:
      return anyTruth(condition.children, node, parent);
    case Condition::Type::Not:
      return negated(conditionTruth(condition.children.front(), node, parent));
    case Condition::Type::Field:
      return testTruth(condition.test, valueOf(node, condition.test.ordinal));
    case Condition::Type::ParentId:
      return parentIdTruth(condition.test, node);
    case Condition::Type::ParentIs:
      return parentIsTruth(condition, parent);
  }
  return Truth::False;
}

// A missing value sorts before any present one.
int compareForOrder(const IndexedNode& left, const IndexedNode& right, uint32_t ordinal) {
  const Comparable* leftValue = valueOf(left, ordinal);
  const Comparable* rightValue = valueOf(right, ordinal);
  if (leftValue == nullptr || rightValue == nullptr) {
    return static_cast<int>(leftValue != nullptr) - static_cast<int>(rightValue != nullptr);
  }
  return compareValues(*leftValue, *rightValue);
}

bool sortsBefore(const std::vector<OrderKey>& keys, const IndexedNode& left, const IndexedNode& right) {
  for (const OrderKey& key : keys) {
    int comparison = compareForOrder(left, right, key.ordinal);
    if (comparison == 0) {
      continue;
    }
    if (key.descending) {
      return comparison > 0;
    }
    return comparison < 0;
  }
  return false;
}

}  // namespace

std::vector<std::string> runQuery(const Query& query, const FieldIndex& index, const std::string& collection) {
  std::vector<std::pair<const std::string*, const IndexedNode*>> hits;
  for (const auto& [nodeId, node] : index.nodesOf(collection)) {
    const IndexedNode* parent = nullptr;
    if (node.kind != "item") {
      continue;
    }
    if (node.parentId.has_value()) {
      parent = index.find(collection, *node.parentId);
    }
    if (conditionTruth(query.where, node, parent) == Truth::True) {
      hits.emplace_back(&nodeId, &node);
    }
  }
  std::stable_sort(hits.begin(), hits.end(), [&](const auto& left, const auto& right) {
    return sortsBefore(query.orderBy, *left.second, *right.second);
  });
  size_t count = hits.size();
  if (query.take.has_value()) {
    count = std::min(count, *query.take);
  }
  std::vector<std::string> ids;
  for (size_t position = 0; position < count; ++position) {
    ids.push_back(*hits[position].first);
  }
  return ids;
}

}  // namespace nw
