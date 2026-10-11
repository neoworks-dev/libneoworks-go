#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "grant.hpp"
#include "node.hpp"

namespace nw {

using NodeLookup = std::function<const Node*(const std::string& nodeId)>;
using ShortcutLookup = std::function<std::vector<const Node*>(const std::string& targetId)>;

// Node and facet keys this installation has been granted or derived. Old epochs
// are retained so children wrapped under a previous parent epoch stay readable.
class Keyring {
 public:
  void addNodeKey(const std::string& nodeId, uint32_t epoch, SymmetricKey key);
  void addFacetKey(const std::string& nodeId, uint32_t epoch, uint32_t facet, SymmetricKey key);

  bool hasNodeKey(const std::string& nodeId, uint32_t epoch) const;
  std::optional<SymmetricKey> findNodeKey(const std::string& nodeId, uint32_t epoch) const;
  // Every known epoch for a node, newest first.
  std::vector<std::pair<uint32_t, SymmetricKey>> allNodeKeys(const std::string& nodeId) const;
  std::optional<SymmetricKey> findFacetKey(const std::string& nodeId, uint32_t epoch, uint32_t facet) const;

  // Opens a grant addressed to the holder of (encPub, encSecret) and stores its keys.
  Status addGrant(const AccessGrant& grant, ByteView encPub, ByteView encSecret);

  // Lets a node's key also be found through a shortcut to it: a shortcut's key is its target's
  // key at the shortcut's epoch.
  void setShortcutLookup(ShortcutLookup lookup) { shortcutLookup_ = std::move(lookup); }

  // Direct entry, else unwrap through the ancestor chain, else through a shortcut. Caches what
  // it derives.
  Result<SymmetricKey> resolveNodeKey(const Node& node, const NodeLookup& lookup);
  Result<SymmetricKey> resolveFacetKey(const Node& node, uint32_t facet, const NodeLookup& lookup);

  void forgetNode(const std::string& nodeId);
  void clear();

 private:
  Result<SymmetricKey> resolveWithDepth(const Node& node, const NodeLookup& lookup, int depth);
  Result<SymmetricKey> unwrapUnderParent(const Node& node, const Node& parent, const NodeLookup& lookup, int depth);
  Result<SymmetricKey> unwrapThroughParent(const Node& node, const NodeLookup& lookup, int depth);
  Result<SymmetricKey> resolveThroughShortcuts(const Node& node, const NodeLookup& lookup, int depth);

  ShortcutLookup shortcutLookup_;

  std::map<std::string, std::map<uint32_t, SymmetricKey>> nodeKeys_;
  std::map<std::string, std::map<std::pair<uint32_t, uint32_t>, SymmetricKey>> facetKeys_;
};

}  // namespace nw
