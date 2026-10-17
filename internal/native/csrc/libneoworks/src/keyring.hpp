#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "grant.hpp"
#include "node.hpp"

namespace nw {

using NodeLookup = std::function<const Node*(const std::string& nodeId)>;
// The key of a row as a reference in a row linking to it carries it; NotFound when none does.
using LinkKeyLookup = std::function<Result<SymmetricKey>(const Node& target)>;

// Row and facet keys this holder has been granted or derived, by row.
class Keyring {
 public:
  void addNodeKey(const std::string& nodeId, SymmetricKey key);
  void addFacetKey(const std::string& nodeId, uint32_t facet, SymmetricKey key);

  bool hasNodeKey(const std::string& nodeId) const;
  std::optional<SymmetricKey> findNodeKey(const std::string& nodeId) const;
  std::optional<SymmetricKey> findFacetKey(const std::string& nodeId, uint32_t facet) const;

  // Opens a grant addressed to the holder of (encPub, encSecret) and stores its keys.
  Status addGrant(const AccessGrant& grant, ByteView encPub, ByteView encSecret);

  // Lets a row's key also be found in the references of the rows linking to it.
  void setLinkKeyLookup(LinkKeyLookup lookup) { linkKeyLookup_ = std::move(lookup); }

  // Direct entry, else unwrap through the row it belongs to, else through a link to it. A key
  // found through a link is kept only when it opens the row's content. Caches what it derives.
  Result<SymmetricKey> resolveNodeKey(const Node& node, const NodeLookup& lookup);
  Result<SymmetricKey> resolveFacetKey(const Node& node, uint32_t facet, const NodeLookup& lookup);

  void forgetNode(const std::string& nodeId);
  void clear();

 private:
  Result<SymmetricKey> resolveWithDepth(const Node& node, const NodeLookup& lookup, int depth);
  Result<SymmetricKey> unwrapThroughParent(const Node& node, const NodeLookup& lookup, int depth);
  Result<SymmetricKey> resolveThroughLinks(const Node& node);

  LinkKeyLookup linkKeyLookup_;

  std::map<std::string, SymmetricKey> nodeKeys_;
  std::map<std::string, std::map<uint32_t, SymmetricKey>> facetKeys_;
};

}  // namespace nw
