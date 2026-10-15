#include "link.hpp"

#include <sodium.h>

#include <algorithm>

#include "files.hpp"
#include "node_content.hpp"
#include "tlv.hpp"

namespace nw {

namespace {

struct DecodedFragment {
  uint32_t epoch = 0;
  SymmetricKey key;
};

Result<DecodedFragment> decodeFragment(std::string_view fragmentKey) {
  std::optional<Bytes> raw = fromBase64Url(fragmentKey);
  if (!raw.has_value() || raw->size() != 4 + kKeyBytes) {
    return Status::Malformed;
  }
  DecodedFragment decoded;
  decoded.epoch = decodeU32(ByteView(*raw).subspan(0, 4)).value();
  Result<SymmetricKey> key = SymmetricKey::fromBytes(ByteView(*raw).subspan(4));
  sodium_memzero(raw->data(), raw->size());
  if (!key.ok()) {
    return key.status();
  }
  decoded.key = key.take();
  return decoded;
}

bool isShortcutTarget(const std::map<std::string, Node>& nodes, const std::string& nodeId) {
  return std::any_of(nodes.begin(), nodes.end(), [&](const auto& entry) {
    return entry.second.targetId.has_value() && *entry.second.targetId == nodeId;
  });
}

// Shortcut targets come with the link but live elsewhere in the tree.
std::string topLevelNodeId(const std::map<std::string, Node>& nodes) {
  std::string found;
  for (const auto& [id, node] : nodes) {
    bool topLevel = !node.parentId.has_value() || nodes.count(*node.parentId) == 0;
    topLevel = topLevel && !isShortcutTarget(nodes, id);
    if (!topLevel) {
      continue;
    }
    if (!found.empty()) {
      return std::string();
    }
    found = id;
  }
  return found;
}

}  // namespace

Result<std::unique_ptr<LinkReader>> LinkReader::open(const Json& pullResponse, std::string_view fragmentKey) {
  Result<DecodedFragment> fragment = decodeFragment(fragmentKey);
  const Json* nodesJson = readArray(pullResponse, "nodes");
  if (!fragment.ok() || nodesJson == nullptr) {
    return Status::Malformed;
  }
  std::unique_ptr<LinkReader> reader(new LinkReader());
  LinkReader* self = reader.get();
  reader->keyring_.setShortcutLookup([self](const std::string& targetId) {
    std::vector<const Node*> shortcuts;
    for (const auto& [id, node] : self->nodes_) {
      if (node.targetId.has_value() && *node.targetId == targetId) {
        shortcuts.push_back(&node);
      }
    }
    return shortcuts;
  });
  for (const Json& entry : *nodesJson) {
    Result<Node> node = nodeFromJson(entry);
    if (node.ok() && validateNodeShape(node.value()) == Status::Ok) {
      std::string id = node.value().id;
      reader->nodes_[id] = node.take();
    }
  }
  reader->linkedNodeId_ = readString(pullResponse, "nodeId").value_or(topLevelNodeId(reader->nodes_));
  const Node* linked = reader->findNode(reader->linkedNodeId_);
  if (linked == nullptr || linked->epoch != fragment.value().epoch) {
    return Status::NotFound;
  }
  reader->keyring_.addNodeKey(linked->id, linked->epoch, std::move(fragment.value().key));
  return reader;
}

std::vector<std::string> LinkReader::nodeIds() const {
  std::vector<std::string> ids;
  for (const auto& entry : nodes_) {
    ids.push_back(entry.first);
  }
  return ids;
}

const Node* LinkReader::findNode(const std::string& nodeId) const {
  auto found = nodes_.find(nodeId);
  if (found == nodes_.end()) {
    return nullptr;
  }
  return &found->second;
}

Result<SymmetricKey> LinkReader::resolveNodeKey(const std::string& nodeId) {
  const Node* node = findNode(nodeId);
  if (node == nullptr) {
    return Status::NotFound;
  }
  NodeLookup lookup = [this](const std::string& id) { return findNode(id); };
  return keyring_.resolveNodeKey(*node, lookup);
}

Status LinkReader::setDescriptor(const std::string& collection, std::string_view descriptorText) {
  Result<std::shared_ptr<const SchemaDescriptor>> schema = parseDescriptor(descriptorText);
  if (!schema.ok()) {
    return schema.status();
  }
  descriptors_[collection] = schema.take();
  return Status::Ok;
}

Result<Json> LinkReader::readStoredContent(const Node& node, const NodeDescriptor& descriptor) {
  NodeLookup lookup = [this](const std::string& id) { return findNode(id); };
  Result<FacetMap> readable = readableFacets(
      node, descriptor, [&](uint32_t tag) { return keyring_.resolveFacetKey(node, tag, lookup); });
  if (!readable.ok()) {
    return readable.status();
  }
  if (readable.value().empty()) {
    return Status::NotFound;
  }
  CodecError error;
  Result<Json> content = decodeContent(descriptor, readable.value(), error);
  if (!content.ok()) {
    return content.status();
  }
  if (checkNodeFiles(descriptor, node, content.value()) != Status::Ok) {
    return Status::IntegrityFailure;
  }
  return content;
}

const NodeDescriptor* LinkReader::descriptorOf(const Node& node) const {
  auto schema = descriptors_.find(node.collection);
  if (schema == descriptors_.end()) {
    return nullptr;
  }
  return schema->second->nodeByKind(node.kind);
}

Result<Json> LinkReader::readNode(const std::string& nodeId) {
  const Node* node = findNode(nodeId);
  if (node == nullptr || node->deleted) {
    return Status::NotFound;
  }
  if (node->kind == "root" || isShortcut(*node)) {
    return Json::object();
  }
  const NodeDescriptor* descriptor = descriptorOf(*node);
  if (descriptor == nullptr) {
    return Status::InvalidState;
  }
  Result<Json> content = readStoredContent(*node, *descriptor);
  if (!content.ok()) {
    return content.status();
  }
  removeFileKeys(*descriptor->model, content.value());
  return content;
}

Result<SymmetricKey> LinkReader::resolveFileKey(const std::string& nodeId, const std::string& objectId) {
  const Node* node = findNode(nodeId);
  if (node == nullptr || node->deleted || node->kind == "root" || isShortcut(*node)) {
    return Status::NotFound;
  }
  const NodeDescriptor* descriptor = descriptorOf(*node);
  if (descriptor == nullptr) {
    return Status::InvalidState;
  }
  Result<Json> content = readStoredContent(*node, *descriptor);
  if (!content.ok()) {
    return content.status();
  }
  return findFileKey(*descriptor->model, content.value(), objectId);
}

}  // namespace nw
