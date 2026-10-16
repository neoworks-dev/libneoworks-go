#include "keyring.hpp"

namespace nw {

namespace {

constexpr int kMaxAncestorDepth = 64;

}  // namespace

void Keyring::addNodeKey(const std::string& nodeId, uint32_t epoch, SymmetricKey key) {
  nodeKeys_[nodeId].insert_or_assign(epoch, std::move(key));
}

void Keyring::addFacetKey(const std::string& nodeId, uint32_t epoch, uint32_t facet, SymmetricKey key) {
  facetKeys_[nodeId].insert_or_assign(std::make_pair(epoch, facet), std::move(key));
}

bool Keyring::hasNodeKey(const std::string& nodeId, uint32_t epoch) const {
  auto byNode = nodeKeys_.find(nodeId);
  if (byNode == nodeKeys_.end()) {
    return false;
  }
  return byNode->second.count(epoch) > 0;
}

std::optional<SymmetricKey> Keyring::findNodeKey(const std::string& nodeId, uint32_t epoch) const {
  auto byNode = nodeKeys_.find(nodeId);
  if (byNode == nodeKeys_.end()) {
    return std::nullopt;
  }
  auto byEpoch = byNode->second.find(epoch);
  if (byEpoch == byNode->second.end()) {
    return std::nullopt;
  }
  return byEpoch->second.clone();
}

std::vector<std::pair<uint32_t, SymmetricKey>> Keyring::allNodeKeys(const std::string& nodeId) const {
  std::vector<std::pair<uint32_t, SymmetricKey>> keys;
  auto byNode = nodeKeys_.find(nodeId);
  if (byNode == nodeKeys_.end()) {
    return keys;
  }
  for (auto entry = byNode->second.rbegin(); entry != byNode->second.rend(); ++entry) {
    keys.emplace_back(entry->first, entry->second.clone());
  }
  return keys;
}

std::optional<SymmetricKey> Keyring::findFacetKey(const std::string& nodeId, uint32_t epoch, uint32_t facet) const {
  auto byNode = facetKeys_.find(nodeId);
  if (byNode == facetKeys_.end()) {
    return std::nullopt;
  }
  auto byFacet = byNode->second.find(std::make_pair(epoch, facet));
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
    addNodeKey(grant.nodeId, grant.epoch, std::move(*opened.value().nodeKey));
  }
  for (auto& [facet, key] : opened.value().facetKeys) {
    addFacetKey(grant.nodeId, grant.epoch, facet, std::move(key));
  }
  return Status::Ok;
}

Result<SymmetricKey> Keyring::unwrapWithKnownKeys(const Node& node, const std::string& parentId) const {
  auto known = nodeKeys_.find(parentId);
  if (known == nodeKeys_.end()) {
    return Status::NotFound;
  }
  for (auto candidate = known->second.rbegin(); candidate != known->second.rend(); ++candidate) {
    Result<SymmetricKey> unwrapped = unwrapNodeKey(candidate->second, *node.wrappedKey, node.id, node.parentId,
                                                   node.epoch, candidate->first);
    if (unwrapped.ok()) {
      return unwrapped;
    }
  }
  return Status::NotFound;
}

void Keyring::addPreviousKeys(const Node& node, const SymmetricKey& nodeKey) {
  Result<KeyHistory> history = previousNodeKeys(node, nodeKey);
  if (!history.ok()) {
    return;
  }
  for (auto& [epoch, key] : history.value()) {
    addNodeKey(node.id, epoch, std::move(key));
  }
}

// A child still wrapped under an earlier key of its parent opens with the parent's key history.
Result<SymmetricKey> Keyring::unwrapUnderParent(const Node& node, const Node& parent, const NodeLookup& lookup,
                                                int depth) {
  Result<SymmetricKey> parentKey = resolveWithDepth(parent, lookup, depth + 1);
  Result<SymmetricKey> unwrapped = unwrapWithKnownKeys(node, parent.id);
  if (unwrapped.ok() || !parentKey.ok()) {
    return unwrapped;
  }
  addPreviousKeys(parent, parentKey.value());
  return unwrapWithKnownKeys(node, parent.id);
}

Result<SymmetricKey> Keyring::unwrapThroughParent(const Node& node, const NodeLookup& lookup, int depth) {
  if (!node.parentId.has_value() || !node.wrappedKey.has_value()) {
    return Status::NotFound;
  }
  const Node* parent = lookup(*node.parentId);
  if (parent == nullptr) {
    return Status::NotFound;
  }
  return unwrapUnderParent(node, *parent, lookup, depth);
}

Result<SymmetricKey> Keyring::resolveThroughShortcuts(const Node& node, const NodeLookup& lookup, int depth) {
  if (!shortcutLookup_) {
    return Status::NotFound;
  }
  for (const Node* shortcut : shortcutLookup_(node.id)) {
    if (shortcut->deleted || shortcut->epoch != node.epoch || shortcut->collection != node.collection) {
      continue;
    }
    Result<SymmetricKey> key = resolveWithDepth(*shortcut, lookup, depth + 1);
    if (key.ok()) {
      return key;
    }
  }
  return Status::NotFound;
}

Result<SymmetricKey> Keyring::resolveWithDepth(const Node& node, const NodeLookup& lookup, int depth) {
  std::optional<SymmetricKey> direct = findNodeKey(node.id, node.epoch);
  if (direct.has_value()) {
    return std::move(*direct);
  }
  if (depth > kMaxAncestorDepth) {
    return Status::Malformed;
  }
  Result<SymmetricKey> resolved = unwrapThroughParent(node, lookup, depth);
  if (!resolved.ok()) {
    resolved = resolveThroughShortcuts(node, lookup, depth);
  }
  if (!resolved.ok()) {
    return resolved;
  }
  addNodeKey(node.id, node.epoch, resolved.value().clone());
  return resolved;
}

Result<SymmetricKey> Keyring::resolveNodeKey(const Node& node, const NodeLookup& lookup) {
  return resolveWithDepth(node, lookup, 0);
}

Result<SymmetricKey> Keyring::resolveFacetKey(const Node& node, uint32_t facet, const NodeLookup& lookup) {
  std::optional<SymmetricKey> stored = findFacetKey(node.id, node.epoch, facet);
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
