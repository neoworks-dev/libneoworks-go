#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace nw {

struct WideInteger {
  bool negative = false;
  uint64_t magnitude = 0;
};

// A field value reduced to something directly comparable. Which member is meaningful follows
// `kind`; two values of the same field always have the same kind.
struct Comparable {
  enum class Kind { Boolean, Integer, Real, Decimal, Text };
  Kind kind = Kind::Text;
  bool boolean = false;
  WideInteger integer;
  double real = 0;
  // Text, or a decimal in its canonical form with a fixed number of fraction digits.
  std::string text;
};

// Negative, zero or positive as `left` sorts before, equal to or after `right`.
int compareValues(const Comparable& left, const Comparable& right);

// The set fields of one node by field ordinal. Unset and null fields are absent.
using FieldValues = std::map<uint32_t, Comparable>;

struct IndexedReference {
  uint32_t fieldOrdinal = 0;
  std::string nodeId;
};

struct IndexedNode {
  std::string kind;
  std::optional<std::string> parentId;
  FieldValues values;
  // Lowercased texts of the @neoworks.searchable fields.
  std::vector<std::string> searchTexts;
  // The nodes its content refers to.
  std::vector<IndexedReference> references;
  // The descriptor node kind of its content: "container", "item" or "asset"; empty for roots.
  std::string model;
};

// The filterable values of every node this holder can read, per collection. Only values live
// here, never ciphertext, and nothing is written to disk.
class FieldIndex {
 public:
  void put(const std::string& collection, const std::string& nodeId, IndexedNode entry);
  void erase(const std::string& nodeId);
  void eraseCollection(const std::string& collection);
  void clear();

  const IndexedNode* find(const std::string& collection, const std::string& nodeId) const;
  // Id order.
  const std::map<std::string, IndexedNode>& nodesOf(const std::string& collection) const;
  bool contains(const std::string& nodeId) const;

 private:
  std::map<std::string, std::map<std::string, IndexedNode>> collections_;
  std::map<std::string, std::string> collectionOfNode_;
};

}  // namespace nw
