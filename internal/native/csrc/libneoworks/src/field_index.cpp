#include "field_index.hpp"

#include <algorithm>

namespace nw {

namespace {

int compareMagnitudes(uint64_t left, uint64_t right) {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

int compareIntegers(const WideInteger& left, const WideInteger& right) {
  bool leftNegative = left.negative && left.magnitude != 0;
  bool rightNegative = right.negative && right.magnitude != 0;
  if (leftNegative != rightNegative) {
    if (leftNegative) {
      return -1;
    }
    return 1;
  }
  int byMagnitude = compareMagnitudes(left.magnitude, right.magnitude);
  if (leftNegative) {
    return -byMagnitude;
  }
  return byMagnitude;
}

int compareTexts(const std::string& left, const std::string& right) {
  int byBytes = left.compare(right);
  if (byBytes < 0) {
    return -1;
  }
  if (byBytes > 0) {
    return 1;
  }
  return 0;
}

// Canonical decimals share one fraction width, so the integer part's length decides first.
size_t integerPartLength(const std::string& decimal) { return std::min(decimal.find('.'), decimal.size()); }

int compareUnsignedDecimals(const std::string& left, const std::string& right) {
  size_t leftIntegerLength = integerPartLength(left);
  size_t rightIntegerLength = integerPartLength(right);
  if (leftIntegerLength != rightIntegerLength) {
    if (leftIntegerLength < rightIntegerLength) {
      return -1;
    }
    return 1;
  }
  return compareTexts(left, right);
}

int compareDecimals(const std::string& left, const std::string& right) {
  bool leftNegative = !left.empty() && left[0] == '-';
  bool rightNegative = !right.empty() && right[0] == '-';
  if (leftNegative != rightNegative) {
    if (leftNegative) {
      return -1;
    }
    return 1;
  }
  if (leftNegative) {
    return compareUnsignedDecimals(right.substr(1), left.substr(1));
  }
  return compareUnsignedDecimals(left, right);
}

int compareReals(double left, double right) {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

}  // namespace

int compareValues(const Comparable& left, const Comparable& right) {
  switch (left.kind) {
    case Comparable::Kind::Boolean:
      return compareMagnitudes(left.boolean, right.boolean);
    case Comparable::Kind::Integer:
      return compareIntegers(left.integer, right.integer);
    case Comparable::Kind::Real:
      return compareReals(left.real, right.real);
    case Comparable::Kind::Decimal:
      return compareDecimals(left.text, right.text);
    case Comparable::Kind::Text:
      return compareTexts(left.text, right.text);
  }
  return 0;
}

int comparePart(const Comparable* left, const Comparable* right) {
  if (left == nullptr || right == nullptr) {
    return static_cast<int>(left != nullptr) - static_cast<int>(right != nullptr);
  }
  return compareValues(*left, *right);
}

int compareToProbe(const IndexEntry& entry, const IndexProbe& probe) {
  for (size_t position = 0; position < probe.prefix.size(); ++position) {
    int comparison = comparePart(entry.parts[position], probe.prefix[position]);
    if (comparison != 0) {
      return comparison;
    }
  }
  if (probe.afterEqual) {
    return -1;
  }
  return 1;
}

bool IndexEntryLess::operator()(const IndexEntry& left, const IndexEntry& right) const {
  for (size_t position = 0; position < left.parts.size(); ++position) {
    int comparison = comparePart(left.parts[position], right.parts[position]);
    if (comparison != 0) {
      return comparison < 0;
    }
  }
  return *left.nodeId < *right.nodeId;
}

namespace {

// The message that holds the last step of `path`; nullptr when a message on the way is unset.
const IndexedMessage* parentOf(const IndexedMessage& root, const OrdinalPath& path) {
  const IndexedMessage* message = &root;
  for (size_t step = 0; step + 1 < path.size(); ++step) {
    auto found = message->messages.find(path[step]);
    if (found == message->messages.end()) {
      return nullptr;
    }
    message = &found->second;
  }
  return message;
}

}  // namespace

const Comparable* findValue(const IndexedMessage& root, const OrdinalPath& path) {
  const IndexedMessage* parent = parentOf(root, path);
  if (parent == nullptr) {
    return nullptr;
  }
  auto found = parent->values.find(path.back());
  if (found == parent->values.end()) {
    return nullptr;
  }
  return &found->second;
}

const std::vector<IndexedMessage>* findElements(const IndexedMessage& root, const OrdinalPath& path) {
  const IndexedMessage* parent = parentOf(root, path);
  if (parent == nullptr) {
    return nullptr;
  }
  auto found = parent->lists.find(path.back());
  if (found == parent->lists.end()) {
    return nullptr;
  }
  return &found->second;
}

namespace {

const Comparable* wholeValueOf(const IndexedNode& node, uint32_t ordinal) {
  auto field = node.fields.values.find(ordinal);
  if (field == node.fields.values.end()) {
    return nullptr;
  }
  return &field->second;
}

IndexEntry entryOf(const SortedIndex& index, const std::string& nodeId, const IndexedNode& node) {
  IndexEntry entry;
  for (uint32_t ordinal : index.fields) {
    entry.parts.push_back(wholeValueOf(node, ordinal));
  }
  entry.nodeId = &nodeId;
  entry.node = &node;
  return entry;
}

bool sameDefinitions(const std::vector<SortedIndex>& kept, const std::vector<IndexDescriptor>& definitions) {
  if (kept.size() != definitions.size()) {
    return false;
  }
  for (size_t position = 0; position < kept.size(); ++position) {
    if (kept[position].fields != definitions[position].fields) {
      return false;
    }
  }
  return true;
}

}  // namespace

std::vector<SortedIndex>* FieldIndex::indexesFor(const std::string& collection, const std::string& table) {
  auto ofCollection = indexes_.find(collection);
  if (ofCollection == indexes_.end()) {
    return nullptr;
  }
  auto ofTable = ofCollection->second.find(table);
  if (ofTable == ofCollection->second.end()) {
    return nullptr;
  }
  return &ofTable->second;
}

void FieldIndex::addToIndexes(const std::string& collection, const std::string& nodeId, const IndexedNode& node) {
  std::vector<SortedIndex>* kept = indexesFor(collection, node.table);
  if (kept == nullptr) {
    return;
  }
  for (SortedIndex& index : *kept) {
    index.entries.insert(entryOf(index, nodeId, node));
  }
}

void FieldIndex::removeFromIndexes(const std::string& collection, const std::string& nodeId, const IndexedNode& node) {
  std::vector<SortedIndex>* kept = indexesFor(collection, node.table);
  if (kept == nullptr) {
    return;
  }
  for (SortedIndex& index : *kept) {
    index.entries.erase(entryOf(index, nodeId, node));
  }
}

void FieldIndex::put(const std::string& collection, const std::string& nodeId, IndexedNode entry) {
  std::map<std::string, IndexedNode>& nodes = collections_[collection];
  auto existing = nodes.find(nodeId);
  if (existing != nodes.end()) {
    removeFromIndexes(collection, existing->first, existing->second);
  }
  auto stored = nodes.insert_or_assign(nodeId, std::move(entry)).first;
  collectionOfNode_[nodeId] = collection;
  addToIndexes(collection, stored->first, stored->second);
}

void FieldIndex::erase(const std::string& nodeId) {
  auto found = collectionOfNode_.find(nodeId);
  if (found == collectionOfNode_.end()) {
    return;
  }
  std::map<std::string, IndexedNode>& nodes = collections_[found->second];
  auto stored = nodes.find(nodeId);
  if (stored != nodes.end()) {
    removeFromIndexes(found->second, stored->first, stored->second);
    nodes.erase(stored);
  }
  collectionOfNode_.erase(found);
}

void FieldIndex::eraseCollection(const std::string& collection) {
  indexes_.erase(collection);
  auto found = collections_.find(collection);
  if (found == collections_.end()) {
    return;
  }
  for (const auto& [nodeId, entry] : found->second) {
    collectionOfNode_.erase(nodeId);
  }
  collections_.erase(found);
}

void FieldIndex::clear() {
  indexes_.clear();
  collections_.clear();
  collectionOfNode_.clear();
}

void FieldIndex::defineIndexes(const std::string& collection, const std::string& table,
                               const std::vector<IndexDescriptor>& definitions) {
  std::vector<SortedIndex>& kept = indexes_[collection][table];
  if (sameDefinitions(kept, definitions)) {
    return;
  }
  kept.clear();
  for (const IndexDescriptor& definition : definitions) {
    kept.push_back(SortedIndex{definition.fields, {}});
  }
  for (const auto& [nodeId, node] : nodesOf(collection)) {
    if (node.table == table) {
      addToIndexes(collection, nodeId, node);
    }
  }
}

const std::vector<SortedIndex>& FieldIndex::indexesOf(const std::string& collection, const std::string& table) const {
  static const std::vector<SortedIndex> none;
  auto ofCollection = indexes_.find(collection);
  if (ofCollection == indexes_.end()) {
    return none;
  }
  auto ofTable = ofCollection->second.find(table);
  if (ofTable == ofCollection->second.end()) {
    return none;
  }
  return ofTable->second;
}

const IndexedNode* FieldIndex::find(const std::string& collection, const std::string& nodeId) const {
  auto found = collections_.find(collection);
  if (found == collections_.end()) {
    return nullptr;
  }
  auto entry = found->second.find(nodeId);
  if (entry == found->second.end()) {
    return nullptr;
  }
  return &entry->second;
}

const std::map<std::string, IndexedNode>& FieldIndex::nodesOf(const std::string& collection) const {
  static const std::map<std::string, IndexedNode> none;
  auto found = collections_.find(collection);
  if (found == collections_.end()) {
    return none;
  }
  return found->second;
}

bool FieldIndex::contains(const std::string& nodeId) const { return collectionOfNode_.count(nodeId) > 0; }

}  // namespace nw
