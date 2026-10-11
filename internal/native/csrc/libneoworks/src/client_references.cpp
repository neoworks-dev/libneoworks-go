#include <algorithm>
#include <deque>

#include "client.hpp"

namespace nw {

namespace {

constexpr int kMaxAncestorWalk = 64;
constexpr size_t kMaxReferencedNodes = 100000;

bool containsFacet(const std::vector<uint32_t>& tags, uint32_t tag) {
  return std::find(tags.begin(), tags.end(), tag) != tags.end();
}

}  // namespace

struct Client::ReferenceWalk {
  std::string startId;
  std::set<std::string> expanded;
  std::deque<std::string> pending;
  std::vector<std::string> referenced;
  std::set<std::string> referencedSet;
};

bool Client::isWithin(const std::string& nodeId, const std::string& ancestorId) const {
  const Node* cursor = database_->findNode(nodeId);
  for (int step = 0; step < kMaxAncestorWalk && cursor != nullptr; ++step) {
    if (cursor->id == ancestorId) {
      return true;
    }
    if (!cursor->parentId.has_value()) {
      return false;
    }
    cursor = database_->findNode(*cursor->parentId);
  }
  return false;
}

void Client::walkReference(ReferenceWalk& walk, const std::string& nodeId) const {
  const Node* target = database_->findNode(nodeId);
  if (target == nullptr || target->deleted || isWithin(nodeId, walk.startId)) {
    return;
  }
  if (walk.referenced.size() >= kMaxReferencedNodes || !walk.referencedSet.insert(nodeId).second) {
    return;
  }
  walk.referenced.push_back(nodeId);
  walk.pending.push_back(nodeId);
}

// The references in the content of `node`, restricted to the fields of the listed facets.
void Client::walkReferences(ReferenceWalk& walk, const Node& node, const FacetTags& facets) const {
  const IndexedNode* entry = index_.find(node.collection, node.id);
  const SchemaDescriptor* schema = descriptorFor(node.collection);
  if (entry == nullptr || schema == nullptr) {
    return;
  }
  const NodeDescriptor* descriptor = schema->nodeByKind(entry->model);
  for (const IndexedReference& reference : entry->references) {
    const FacetDescriptor* facet = nullptr;
    if (descriptor != nullptr) {
      facet = descriptor->facetOfField(reference.fieldOrdinal);
    }
    bool shared = !facets.has_value() || (facet != nullptr && containsFacet(*facets, facet->tag));
    if (shared) {
      walkReference(walk, reference.nodeId);
    }
  }
}

// A shortcut opens its target, so the target's references go along with it.
void Client::walkNode(ReferenceWalk& walk, const Node& node, const FacetTags& facets) const {
  if (node.deleted) {
    return;
  }
  if (!isShortcut(node)) {
    walkReferences(walk, node, facets);
    return;
  }
  const Node* target = database_->findNode(*node.targetId);
  if (target != nullptr) {
    walkNode(walk, *target, std::nullopt);
  }
}

void Client::walkSubtree(ReferenceWalk& walk, const std::string& rootId, const FacetTags& facets) const {
  std::deque<std::string> queue{rootId};
  while (!queue.empty()) {
    std::string nodeId = queue.front();
    queue.pop_front();
    const Node* node = database_->findNode(nodeId);
    if (node == nullptr || node->deleted) {
      continue;
    }
    walkNode(walk, *node, facets);
    for (const std::string& childId : database_->childrenOf(nodeId)) {
      queue.push_back(childId);
    }
  }
}

std::vector<std::string> Client::referencedNodesOf(const std::string& startId, const FacetTags& facets) const {
  ReferenceWalk walk;
  walk.startId = startId;
  walk.expanded.insert(startId);
  walkSubtree(walk, startId, facets);
  while (!walk.pending.empty()) {
    std::string rootId = walk.pending.front();
    walk.pending.pop_front();
    if (walk.expanded.insert(rootId).second) {
      walkSubtree(walk, rootId, std::nullopt);
    }
  }
  return walk.referenced;
}

Status Client::requireShareable(const std::vector<std::string>& nodeIds) {
  for (const std::string& nodeId : nodeIds) {
    const Node* node = database_->findNode(nodeId);
    if (node != nullptr && canManageAccess(*node) && resolveNodeKey(nodeId).ok()) {
      continue;
    }
    lastContentError_.status = Status::Forbidden;
    lastContentError_.path = nodeId;
    lastContentError_.reason = "asset_not_shareable";
    return Status::Forbidden;
  }
  return Status::Ok;
}

bool Client::principalHasAccess(const Node& node, const std::string& principalType,
                                const std::string& principalId) const {
  if (principalType == "user" && trustedOwnerOf(node) == principalId) {
    return true;
  }
  const Node* cursor = &node;
  for (int step = 0; step < kMaxAncestorWalk && cursor != nullptr; ++step) {
    if (hasActiveGrant(cursor->id, principalType, principalId)) {
      return true;
    }
    if (!cursor->parentId.has_value()) {
      return false;
    }
    cursor = database_->findNode(*cursor->parentId);
  }
  return false;
}

bool Client::hasActiveGrant(const std::string& nodeId, const std::string& principalType,
                            const std::string& principalId) const {
  for (const AccessGrant& grant : database_->grantsForNode(nodeId)) {
    if (grant.principalType == principalType && grant.principalId == principalId && !grant.revokedAt.has_value()) {
      return true;
    }
  }
  return false;
}

// `share` names the person; the referenced node gets whole-node read access.
Status Client::grantReferenced(const std::string& nodeId, const ShareRequest& share) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr) {
    return Status::NotFound;
  }
  if (principalHasAccess(*node, share.principalType, share.principalId)) {
    return Status::Ok;
  }
  ShareRequest read = share;
  read.nodeId = nodeId;
  read.role = "read";
  read.facets = std::nullopt;
  return grantNode(read).status();
}

// The people holding an unrevoked whole-node grant on the node or an ancestor, other than its owner
// and this holder.
std::vector<std::string> Client::peopleWithAccessTo(const Node& node) const {
  std::string owner = trustedOwnerOf(node);
  std::set<std::string> people;
  const Node* cursor = &node;
  for (int step = 0; step < kMaxAncestorWalk && cursor != nullptr; ++step) {
    for (const AccessGrant& grant : database_->grantsForNode(cursor->id)) {
      bool wholeNode = !grant.facets.has_value();
      bool otherPerson = grant.principalType == "user" && grant.principalId != owner && grant.principalId != signer_.authorId;
      if (wholeNode && otherPerson && !grant.revokedAt.has_value()) {
        people.insert(grant.principalId);
      }
    }
    if (!cursor->parentId.has_value()) {
      break;
    }
    cursor = database_->findNode(*cursor->parentId);
  }
  return std::vector<std::string>(people.begin(), people.end());
}

void Client::grantReferencesToHolders(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted || node->kind == "root") {
    return;
  }
  std::vector<std::string> people = peopleWithAccessTo(*node);
  if (people.empty()) {
    return;
  }
  std::vector<std::string> referenced = referencedNodesOf(nodeId, std::nullopt);
  for (const std::string& personId : people) {
    Result<Bytes> encPub = encPubFor("user", personId);
    if (!encPub.ok()) {
      continue;
    }
    ShareRequest share;
    share.principalType = "user";
    share.principalId = personId;
    share.principalEncPub = encPub.take();
    for (const std::string& referencedId : referenced) {
      const Node* asset = database_->findNode(referencedId);
      if (asset != nullptr && canManageAccess(*asset)) {
        grantReferenced(referencedId, share);
      }
    }
  }
}

// Whether a node that `principal` can open refers to `nodeId`.
bool Client::isReferencedForPrincipal(const std::string& nodeId, const std::string& principalType,
                                      const std::string& principalId) const {
  for (const std::string& candidateId : database_->allNodeIds()) {
    const Node* candidate = database_->findNode(candidateId);
    if (candidate == nullptr || candidate->deleted || !principalHasAccess(*candidate, principalType, principalId)) {
      continue;
    }
    ReferenceWalk walk;
    walkNode(walk, *candidate, std::nullopt);
    if (walk.referencedSet.count(nodeId) > 0) {
      return true;
    }
  }
  return false;
}

// After a person lost access to a node: revokes the grants they hold on what it referred to, unless
// something else they can still open refers to it. Only grants made directly on the referenced node
// are removed; access that comes from an ancestor stays.
void Client::revokeUnreferenced(const std::string& startId, const std::string& principalType,
                                const std::string& principalId, RotationReport& report) {
  for (const std::string& referencedId : referencedNodesOf(startId, std::nullopt)) {
    const Node* referenced = database_->findNode(referencedId);
    bool revocable = referenced != nullptr && hasActiveGrant(referencedId, principalType, principalId) &&
                     canManageAccess(*referenced);
    if (!revocable || isReferencedForPrincipal(referencedId, principalType, principalId)) {
      continue;
    }
    Result<RotationReport> revoked = revokeAccess(referencedId, principalType, principalId);
    if (!revoked.ok()) {
      continue;
    }
    for (const std::string& rotatedId : revoked.value().rotatedNodeIds) {
      report.rotatedNodeIds.push_back(rotatedId);
    }
    for (const std::string& stale : revoked.value().blobReencryptionRequired) {
      report.blobReencryptionRequired.push_back(stale);
    }
  }
}

}  // namespace nw
