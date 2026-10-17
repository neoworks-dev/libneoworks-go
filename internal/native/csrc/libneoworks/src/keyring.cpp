#include "keyring.hpp"

namespace nw {

namespace {

constexpr int kMaxAncestorDepth = 64;

}  // namespace

void Keyring::addNodeKey(const std::string& nodeId, SymmetricKey key) {
  nodeKeys_.insert_or_assign(nodeId, std::move(key));
}

void Keyring::addFacetKey(const std::string& nodeId, uint32_t facet, SymmetricKey key) {
  facetKeys_[nodeId].insert_or_assign(facet, std::move(key));
}

bool Keyring::hasNodeKey(const std::string& nodeId) const { return nodeKeys_.count(nodeId) > 0; }

std::optional<SymmetricKey> Keyring::findNodeKey(const std::string& nodeId) const {
  auto found = nodeKeys_.find(nodeId);
  if (found == nodeKeys_.end()) {
    return std::nullopt;
  }
  return found->second.clone();
}

std::optional<SymmetricKey> Keyring::findFacetKey(const std::string& nodeId, uint32_t facet) const {
  auto byNode = facetKeys_.find(nodeId);
  if (byNode == facetKeys_.end()) {
    return std::nullopt;
  }
  auto byFacet = byNode->second.find(facet);
  if (byFacet == byNode->second.end()) {
    return std::nullopt;
  }
  return byFacet->second.clone();
}

Status Keyring::addGrant(const AccessGrant& grant, ByteView encPub, ByteView encSecret) {
  Result<OpenedGrant> opened = openGrant(encPub, encSecret, grant);
  if (!opened.ok()) {
    return opened.status();
  }
  if (opened.value().nodeKey.has_value()) {
    addNodeKey(grant.nodeId, std::move(*opened.value().nodeKey));
  }
  for (auto& [facet, key] : opened.value().facetKeys) {
    addFacetKey(grant.nodeId, facet, std::move(key));
  }
  return Status::Ok;
}

Result<SymmetricKey> Keyring::unwrapThroughParent(const Node& node, const NodeLookup& lookup, int depth) {
  if (!node.parentId.has_value() || !node.wrappedKey.has_value()) {
    return Status::NotFound;
  }
  const Node* parent = lookup(*node.parentId);
  if (parent == nullptr) {
    return Status::NotFound;
  }
  Result<SymmetricKey> parentKey = resolveWithDepth(*parent, lookup, depth + 1);
  if (!parentKey.ok()) {
    return parentKey.status();
  }
  return unwrapNodeKey(parentKey.value(), *node.wrappedKey, node.id, node.parentId);
}

namespace {

// A link's key is the linking writer's claim; it counts once it decrypts one of the row's facets.
bool opensContent(const Node& node, const SymmetricKey& key) {
  Result<FacetMap> facets = parseContent(node.content);
  if (!facets.ok() || facets.value().empty()) {
    return false;
  }
  uint32_t tag = facets.value().begin()->first;
  return decryptFacet(facetKey(key, tag), node, tag).ok();
}

}  // namespace

Result<SymmetricKey> Keyring::resolveThroughLinks(const Node& node) {
  if (!linkKeyLookup_) {
    return Status::NotFound;
  }
  Result<SymmetricKey> key = linkKeyLookup_(node);
  if (!key.ok()) {
    return key;
  }
  if (!opensContent(node, key.value())) {
    return Status::NotFound;
  }
  return key;
}

Result<SymmetricKey> Keyring::resolveWithDepth(const Node& node, const NodeLookup& lookup, int depth) {
  std::optional<SymmetricKey> direct = findNodeKey(node.id);
  if (direct.has_value()) {
    return std::move(*direct);
  }
  if (depth > kMaxAncestorDepth) {
    return Status::Malformed;
  }
  Result<SymmetricKey> resolved = unwrapThroughParent(node, lookup, depth);
  if (!resolved.ok()) {
    resolved = resolveThroughLinks(node);
  }
  if (!resolved.ok()) {
    return resolved;
  }
  addNodeKey(node.id, resolved.value().clone());
  return resolved;
}

Result<SymmetricKey> Keyring::resolveNodeKey(const Node& node, const NodeLookup& lookup) {
  return resolveWithDepth(node, lookup, 0);
}

Result<SymmetricKey> Keyring::resolveFacetKey(const Node& node, uint32_t facet, const NodeLookup& lookup) {
  std::optional<SymmetricKey> stored = findFacetKey(node.id, facet);
  if (stored.has_value()) {
    return std::move(*stored);
  }
  Result<SymmetricKey> nodeKey = resolveNodeKey(node, lookup);
  if (!nodeKey.ok()) {
    return nodeKey.status();
  }
  return nw::facetKey(nodeKey.value(), facet);
}

void Keyring::forgetNode(const std::string& nodeId) {
  nodeKeys_.erase(nodeId);
  facetKeys_.erase(nodeId);
}

void Keyring::clear() {
  nodeKeys_.clear();
  facetKeys_.clear();
}

}  // namespace nw
