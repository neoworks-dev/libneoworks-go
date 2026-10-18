#include <algorithm>

#include <iterator>
#include <set>

#include "query.hpp"
#include "query_fields.hpp"
#include "query_plan.hpp"

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

bool isTextOperator(FilterOperator filterOperator) {
  return filterOperator == FilterOperator::Contains || filterOperator == FilterOperator::StartsWith ||
         filterOperator == FilterOperator::EndsWith;
}

bool matchesPresentText(const FieldTest& test, const Comparable& value) {
  const std::string& part = test.operands.front()->text;
  if (!test.insensitive) {
    return textHolds(test.filterOperator, value.text, part);
  }
  return textHolds(test.filterOperator, lowercaseAscii(value.text), part);
}

bool matchesPresentOrder(const FieldTest& test, const Comparable& value) {
  const Comparable& operand = *test.operands.front();
  if (!test.insensitive || value.kind != Comparable::Kind::Text) {
    return orderingHolds(test.filterOperator, compareValues(value, operand));
  }
  Comparable folded = value;
  folded.text = lowercaseAscii(value.text);
  return orderingHolds(test.filterOperator, compareValues(folded, operand));
}

bool matchesPresentValue(const FieldTest& test, const Comparable& value) {
  if (isTextOperator(test.filterOperator)) {
    return matchesPresentText(test, value);
  }
  return matchesPresentOrder(test, value);
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

Truth conditionTruth(const Condition& condition, const IndexedMessage& scope);

// True when every item is, false as soon as one is, otherwise unknown. No items is true.
template <typename Items, typename Evaluate>
Truth allOf(const Items& items, Evaluate evaluate) {
  Truth combined = Truth::True;
  for (const auto& item : items) {
    Truth truth = evaluate(item);
    if (truth == Truth::False) {
      return Truth::False;
    }
    if (truth == Truth::Unknown) {
      combined = Truth::Unknown;
    }
  }
  return combined;
}

// True as soon as one item is, otherwise unknown when one is. No items is false.
template <typename Items, typename Evaluate>
Truth anyOf(const Items& items, Evaluate evaluate) {
  Truth combined = Truth::False;
  for (const auto& item : items) {
    Truth truth = evaluate(item);
    if (truth == Truth::True) {
      return Truth::True;
    }
    if (truth == Truth::Unknown) {
      combined = Truth::Unknown;
    }
  }
  return combined;
}

const std::vector<IndexedMessage>& elementsOf(const IndexedMessage& scope, const OrdinalPath& listPath) {
  static const std::vector<IndexedMessage> none;
  const std::vector<IndexedMessage>* elements = findElements(scope, listPath);
  if (elements == nullptr) {
    return none;
  }
  return *elements;
}

// Whether some element has the given truth under the child condition.
bool someElementIs(const std::vector<IndexedMessage>& elements, const Condition& child, Truth wanted) {
  return std::any_of(elements.begin(), elements.end(), [&](const IndexedMessage& element) {
    return conditionTruth(child, element) == wanted;
  });
}

// As in Prisma, a quantifier is a plain yes or no: an element for which the filter is unknown is neither
// a match nor a violation. `every` holds unless an element fails the filter, so an element without the
// field passes `every: { note: "x" }`; test `{ note: { not: null } }` to demand the field.
Truth elementsTruth(const Condition& condition, const IndexedMessage& scope) {
  const std::vector<IndexedMessage>& elements = elementsOf(scope, condition.listPath);
  const Condition& child = condition.children.front();
  if (condition.quantifier == Quantifier::Every) {
    return truthOf(!someElementIs(elements, child, Truth::False));
  }
  bool matches = someElementIs(elements, child, Truth::True);
  if (condition.quantifier == Quantifier::Some) {
    return truthOf(matches);
  }
  return truthOf(!matches);
}

// `scope` is the row's content, or the list element the condition is tested inside of.
Truth conditionTruth(const Condition& condition, const IndexedMessage& scope) {
  switch (condition.type) {
    case Condition::Type::All:
      return allOf(condition.children, [&](const Condition& child) { return conditionTruth(child, scope); });
    case Condition::Type::Any:
      return anyOf(condition.children, [&](const Condition& child) { return conditionTruth(child, scope); });
    case Condition::Type::Not:
      return negated(conditionTruth(condition.children.front(), scope));
    case Condition::Type::Field:
      return testTruth(condition.test, findValue(scope, condition.test.path));
    case Condition::Type::Elements:
      return elementsTruth(condition, scope);
  }
  return Truth::False;
}

// A missing value sorts before any present one.
int compareForOrder(const IndexedNode& left, const IndexedNode& right, const OrderKey& key) {
  const Comparable* leftValue = findValue(left.fields, key.path);
  const Comparable* rightValue = findValue(right.fields, key.path);
  if (leftValue == nullptr || rightValue == nullptr) {
    return static_cast<int>(leftValue != nullptr) - static_cast<int>(rightValue != nullptr);
  }
  return compareValues(*leftValue, *rightValue);
}

bool sortsBefore(const std::vector<OrderKey>& keys, const IndexedNode& left, const IndexedNode& right) {
  for (const OrderKey& key : keys) {
    int comparison = compareForOrder(left, right, key);
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

// The row a single reference names, when it is live and readable here.
std::optional<std::string> includedRow(const FieldIndex& index, const IndexedNode& node, uint32_t ordinal) {
  for (const IndexedReference& reference : node.references) {
    if (reference.fieldOrdinal == ordinal && index.contains(reference.rowId)) {
      return reference.rowId;
    }
  }
  return std::nullopt;
}

std::vector<std::pair<std::string, std::optional<std::string>>> includedRows(const Query& query, const FieldIndex& index,
                                                                             const IndexedNode& node) {
  std::vector<std::pair<std::string, std::optional<std::string>>> included;
  for (const IncludedField& field : query.include) {
    included.emplace_back(field.name, includedRow(index, node, field.ordinal));
  }
  return included;
}

using Hit = std::pair<const std::string*, const IndexedNode*>;

bool matches(const Query& query, const IndexedNode& node) {
  return conditionTruth(query.where, node.fields) == Truth::True;
}

bool sortsByIdBefore(const Hit& left, const Hit& right) { return *left.first < *right.first; }

std::vector<Hit> scannedHits(const Query& query, const FieldIndex& index, const std::string& collection,
                             const std::string& table) {
  std::vector<Hit> hits;
  for (const auto& [nodeId, node] : index.nodesOf(collection)) {
    if (node.table == table && matches(query, node)) {
      hits.emplace_back(&nodeId, &node);
    }
  }
  return hits;
}

using EntryIterator = std::set<IndexEntry, IndexEntryLess>::const_iterator;

struct EntryRange {
  EntryIterator first;
  EntryIterator last;
};

EntryRange rangeOf(const IndexScan& scan) {
  const std::set<IndexEntry, IndexEntryLess>& entries = scan.index->entries;
  EntryRange range{entries.lower_bound(scan.lower), entries.lower_bound(scan.upper)};
  bool inverted = range.first != entries.end() && compareToProbe(*range.first, scan.upper) >= 0;
  if (inverted) {
    range.last = range.first;
  }
  return range;
}

bool sameOrderValues(const IndexEntry& left, const IndexEntry& right, size_t partCount) {
  for (size_t position = 0; position < partCount; ++position) {
    if (comparePart(left.parts[position], right.parts[position]) != 0) {
      return false;
    }
  }
  return true;
}

// Rows with equal order values go by id, as they do when the rows are sorted after the scan.
void flushGroup(std::vector<Hit>& group, std::vector<Hit>& hits) {
  std::sort(group.begin(), group.end(), sortsByIdBefore);
  hits.insert(hits.end(), group.begin(), group.end());
  group.clear();
}

bool takeReached(const Query& query, const std::vector<Hit>& hits) {
  return query.take.has_value() && hits.size() >= *query.take;
}

// Reads entries in index order and stops after the group of equal order values that fills `take`.
template <typename Iterator>
std::vector<Hit> orderedHits(const Query& query, const IndexScan& scan, Iterator first, Iterator last) {
  std::vector<Hit> hits;
  std::vector<Hit> group;
  const IndexEntry* groupStart = nullptr;
  for (Iterator entry = first; entry != last; ++entry) {
    bool newGroup = groupStart == nullptr || !sameOrderValues(*groupStart, *entry, scan.orderPartCount);
    if (newGroup) {
      flushGroup(group, hits);
      groupStart = &*entry;
    }
    if (newGroup && takeReached(query, hits)) {
      return hits;
    }
    if (matches(query, *entry->node)) {
      group.emplace_back(entry->nodeId, entry->node);
    }
  }
  flushGroup(group, hits);
  return hits;
}

std::vector<Hit> orderedIndexHits(const Query& query, const IndexScan& scan) {
  EntryRange range = rangeOf(scan);
  if (scan.descending) {
    return orderedHits(query, scan, std::make_reverse_iterator(range.last), std::make_reverse_iterator(range.first));
  }
  return orderedHits(query, scan, range.first, range.last);
}

std::vector<Hit> indexedHits(const Query& query, const IndexScan& scan) {
  if (scan.ordersResult) {
    return orderedIndexHits(query, scan);
  }
  EntryRange range = rangeOf(scan);
  std::vector<Hit> hits;
  for (EntryIterator entry = range.first; entry != range.last; ++entry) {
    if (matches(query, *entry->node)) {
      hits.emplace_back(entry->nodeId, entry->node);
    }
  }
  std::sort(hits.begin(), hits.end(), sortsByIdBefore);
  return hits;
}

}  // namespace

std::vector<QueryRow> runQuery(const Query& query, const FieldIndex& index, const std::string& collection,
                               const std::string& table) {
  std::optional<IndexScan> scan = planIndexScan(query, index.indexesOf(collection, table));
  std::vector<Hit> hits;
  bool ordered = false;
  if (scan.has_value()) {
    hits = indexedHits(query, *scan);
    ordered = scan->ordersResult;
  } else {
    hits = scannedHits(query, index, collection, table);
  }
  if (!ordered) {
    std::stable_sort(hits.begin(), hits.end(), [&](const Hit& left, const Hit& right) {
      return sortsBefore(query.orderBy, *left.second, *right.second);
    });
  }
  size_t count = hits.size();
  if (query.take.has_value()) {
    count = std::min(count, *query.take);
  }
  std::vector<QueryRow> rows;
  for (size_t position = 0; position < count; ++position) {
    rows.push_back(QueryRow{*hits[position].first, includedRows(query, index, *hits[position].second)});
  }
  return rows;
}

}  // namespace nw
