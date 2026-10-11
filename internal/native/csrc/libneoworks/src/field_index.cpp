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

void FieldIndex::put(const std::string& collection, const std::string& nodeId, IndexedNode entry) {
  collections_[collection].insert_or_assign(nodeId, std::move(entry));
  collectionOfNode_[nodeId] = collection;
}

void FieldIndex::erase(const std::string& nodeId) {
  auto found = collectionOfNode_.find(nodeId);
  if (found == collectionOfNode_.end()) {
    return;
  }
  collections_[found->second].erase(nodeId);
  collectionOfNode_.erase(found);
}

void FieldIndex::eraseCollection(const std::string& collection) {
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
  collections_.clear();
  collectionOfNode_.clear();
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
