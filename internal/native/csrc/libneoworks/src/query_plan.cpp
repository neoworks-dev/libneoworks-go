#include "query_plan.hpp"

#include <map>

namespace nw {

namespace {

// What a `where` demands of each field, read from the tests that every matching row must pass.
struct Bounds {
  const Comparable* lower = nullptr;
  bool lowerExcluded = false;
  const Comparable* upper = nullptr;
  bool upperIncluded = false;
};

struct Predicates {
  // A null operand is nullptr.
  std::map<uint32_t, const Comparable*> equalities;
  std::map<uint32_t, Bounds> ranges;
};

bool isOrderingTest(FilterOperator filterOperator) {
  return filterOperator == FilterOperator::Lt || filterOperator == FilterOperator::Lte ||
         filterOperator == FilterOperator::Gt || filterOperator == FilterOperator::Gte;
}

bool isEqualityTest(const FieldTest& test) {
  bool single = test.filterOperator == FilterOperator::Equals ||
                (test.filterOperator == FilterOperator::In && test.operands.size() == 1);
  return single && !test.insensitive;
}

void addRange(const FieldTest& test, Predicates& predicates) {
  Bounds& bounds = predicates.ranges[test.ordinal];
  const Comparable* operand = &*test.operands.front();
  bool isLower = test.filterOperator == FilterOperator::Gt || test.filterOperator == FilterOperator::Gte;
  if (isLower && bounds.lower == nullptr) {
    bounds.lower = operand;
    bounds.lowerExcluded = test.filterOperator == FilterOperator::Gt;
  }
  if (!isLower && bounds.upper == nullptr) {
    bounds.upper = operand;
    bounds.upperIncluded = test.filterOperator == FilterOperator::Lte;
  }
}

void addTest(const FieldTest& test, Predicates& predicates) {
  if (test.member != kWholeValue) {
    return;
  }
  if (isEqualityTest(test)) {
    const std::optional<Comparable>& operand = test.operands.front();
    const Comparable* value = nullptr;
    if (operand.has_value()) {
      value = &*operand;
    }
    predicates.equalities.emplace(test.ordinal, value);
    return;
  }
  if (isOrderingTest(test.filterOperator) && !test.insensitive) {
    addRange(test, predicates);
  }
}

void collectPredicates(const Condition& condition, Predicates& predicates) {
  if (condition.type == Condition::Type::Field) {
    addTest(condition.test, predicates);
    return;
  }
  if (condition.type != Condition::Type::All) {
    return;
  }
  for (const Condition& child : condition.children) {
    collectPredicates(child, predicates);
  }
}

std::vector<const Comparable*> equalityPrefix(const SortedIndex& index, const Predicates& predicates) {
  std::vector<const Comparable*> prefix;
  for (uint32_t ordinal : index.fields) {
    auto found = predicates.equalities.find(ordinal);
    if (found == predicates.equalities.end()) {
      break;
    }
    prefix.push_back(found->second);
  }
  return prefix;
}

const Bounds* rangeAfter(const SortedIndex& index, size_t prefixSize, const Predicates& predicates) {
  if (prefixSize >= index.fields.size()) {
    return nullptr;
  }
  auto found = predicates.ranges.find(index.fields[prefixSize]);
  if (found == predicates.ranges.end()) {
    return nullptr;
  }
  return &found->second;
}

// Whether the index fields after the equality prefix list the `orderBy` keys, all in one direction.
bool indexOrdersBy(const SortedIndex& index, size_t prefixSize, const std::vector<OrderKey>& orderBy) {
  if (orderBy.empty() || prefixSize + orderBy.size() > index.fields.size()) {
    return false;
  }
  for (size_t position = 0; position < orderBy.size(); ++position) {
    const OrderKey& key = orderBy[position];
    bool matches = key.member == kWholeValue && key.ordinal == index.fields[prefixSize + position] &&
                   key.descending == orderBy.front().descending;
    if (!matches) {
      return false;
    }
  }
  return true;
}

IndexProbe lowerProbe(std::vector<const Comparable*> prefix, const Bounds* range) {
  IndexProbe probe;
  probe.prefix = std::move(prefix);
  if (range == nullptr) {
    return probe;
  }
  if (range->lower != nullptr) {
    probe.prefix.push_back(range->lower);
    probe.afterEqual = range->lowerExcluded;
    return probe;
  }
  // Only an upper bound: rows without a value never satisfy it.
  probe.prefix.push_back(nullptr);
  probe.afterEqual = true;
  return probe;
}

IndexProbe upperProbe(std::vector<const Comparable*> prefix, const Bounds* range) {
  IndexProbe probe;
  probe.prefix = std::move(prefix);
  probe.afterEqual = true;
  if (range != nullptr && range->upper != nullptr) {
    probe.prefix.push_back(range->upper);
    probe.afterEqual = range->upperIncluded;
  }
  return probe;
}

struct Candidate {
  IndexScan scan;
  int score = 0;
};

// Equality on a leading field narrows most, then a range, then reading in the wanted order.
Candidate candidateFor(const SortedIndex& index, const Predicates& predicates, const std::vector<OrderKey>& orderBy) {
  std::vector<const Comparable*> prefix = equalityPrefix(index, predicates);
  const Bounds* range = rangeAfter(index, prefix.size(), predicates);
  bool ordered = indexOrdersBy(index, prefix.size(), orderBy);
  Candidate candidate;
  candidate.score = static_cast<int>(prefix.size()) * 4;
  if (range != nullptr) {
    candidate.score += 2;
  }
  if (ordered) {
    candidate.score += 1;
  }
  candidate.scan.index = &index;
  candidate.scan.lower = lowerProbe(prefix, range);
  candidate.scan.upper = upperProbe(prefix, range);
  candidate.scan.ordersResult = ordered;
  if (ordered) {
    candidate.scan.descending = orderBy.front().descending;
    candidate.scan.orderPartCount = prefix.size() + orderBy.size();
  }
  return candidate;
}

}  // namespace

std::optional<IndexScan> planIndexScan(const Query& query, const std::vector<SortedIndex>& indexes) {
  Predicates predicates;
  collectPredicates(query.where, predicates);
  std::optional<Candidate> best;
  for (const SortedIndex& index : indexes) {
    Candidate candidate = candidateFor(index, predicates, query.orderBy);
    if (candidate.score > 0 && (!best.has_value() || candidate.score > best->score)) {
      best = std::move(candidate);
    }
  }
  if (!best.has_value()) {
    return std::nullopt;
  }
  return best->scan;
}

}  // namespace nw
