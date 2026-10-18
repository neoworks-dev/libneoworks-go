#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "descriptor.hpp"

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

// The ordinals of the fields that lead from a row, or from a list element, down to a value. Every
// step but the last names a singular embedded message or File; the last names the value, or the list
// field when the path leads to the elements of a list.
using OrdinalPath = std::vector<uint32_t>;

// Where the value of a list element that is a plain value, not a message, is kept.
constexpr uint32_t kWholeValue = 0;

// The comparable values of one message: a row's content, an embedded message, a File or one
// element of a list or map. Unset and null fields are absent.
struct IndexedMessage {
  // The set singular fields that have a value type by ordinal; for a File the name, media type and
  // size by the ordinals of fileModel().
  std::map<uint32_t, Comparable> values;
  // The singular embedded messages and Files that have anything indexed.
  std::map<uint32_t, IndexedMessage> messages;
  // The elements of the set lists and the values of the set maps by field ordinal, in content order.
  // An element that is a plain value keeps it at `kWholeValue`.
  std::map<uint32_t, std::vector<IndexedMessage>> lists;

  bool empty() const { return values.empty() && messages.empty() && lists.empty(); }
};

// The value `path` leads to; nullptr when it or a message on the way is unset.
const Comparable* findValue(const IndexedMessage& root, const OrdinalPath& path);

// The elements of the list `path` leads to; nullptr when it or a message on the way is unset.
const std::vector<IndexedMessage>* findElements(const IndexedMessage& root, const OrdinalPath& path);

struct IndexedReference {
  uint32_t fieldOrdinal = 0;
  std::string rowId;
};

struct IndexedNode {
  // The row's table, by model name.
  std::string table;
  IndexedMessage fields;
  // The rows its content refers to.
  std::vector<IndexedReference> references;
};

// Negative, zero or positive as the value sorts before, equal to or after the other; an unset value
// sorts before every set one.
int comparePart(const Comparable* left, const Comparable* right);

// A row's place in a sorted index: the values of the index's fields, nullptr for an unset one.
// They point into the row's IndexedNode, which stays where it is while the row is indexed.
struct IndexEntry {
  std::vector<const Comparable*> parts;
  const std::string* nodeId = nullptr;
  const IndexedNode* node = nullptr;
};

// A position between the entries whose leading values differ from `prefix` and those that match it:
// before all entries starting with `prefix`, or after all of them.
struct IndexProbe {
  std::vector<const Comparable*> prefix;
  bool afterEqual = false;
};

// Negative when the entry sorts before the probe, positive when after; never zero.
int compareToProbe(const IndexEntry& entry, const IndexProbe& probe);

struct IndexEntryLess {
  using is_transparent = void;
  bool operator()(const IndexEntry& left, const IndexEntry& right) const;
  bool operator()(const IndexEntry& entry, const IndexProbe& probe) const { return compareToProbe(entry, probe) < 0; }
  bool operator()(const IndexProbe& probe, const IndexEntry& entry) const { return compareToProbe(entry, probe) > 0; }
};

// The rows of one table sorted by the values of `fields`, then by id.
struct SortedIndex {
  std::vector<uint32_t> fields;
  std::set<IndexEntry, IndexEntryLess> entries;
};

// The filterable values of every live row this holder can read, per collection, and the sorted
// indexes kept over them. Only values live here, never ciphertext, and nothing is written to disk.
class FieldIndex {
 public:
  FieldIndex() = default;
  // Index entries point into the rows, so a copy would point into the original.
  FieldIndex(const FieldIndex&) = delete;
  FieldIndex& operator=(const FieldIndex&) = delete;

  void put(const std::string& collection, const std::string& nodeId, IndexedNode entry);
  void erase(const std::string& nodeId);
  void eraseCollection(const std::string& collection);
  void clear();

  // Keeps exactly these sorted indexes for the rows of `table`, building the ones not kept yet from
  // the rows already here.
  void defineIndexes(const std::string& collection, const std::string& table,
                     const std::vector<IndexDescriptor>& definitions);
  const std::vector<SortedIndex>& indexesOf(const std::string& collection, const std::string& table) const;

  const IndexedNode* find(const std::string& collection, const std::string& nodeId) const;
  // Id order.
  const std::map<std::string, IndexedNode>& nodesOf(const std::string& collection) const;
  bool contains(const std::string& nodeId) const;

 private:
  std::vector<SortedIndex>* indexesFor(const std::string& collection, const std::string& table);
  void addToIndexes(const std::string& collection, const std::string& nodeId, const IndexedNode& node);
  void removeFromIndexes(const std::string& collection, const std::string& nodeId, const IndexedNode& node);

  std::map<std::string, std::map<std::string, IndexedNode>> collections_;
  std::map<std::string, std::string> collectionOfNode_;
  std::map<std::string, std::map<std::string, std::vector<SortedIndex>>> indexes_;
};

}  // namespace nw
