#include "link.hpp"

#include <sodium.h>

#include <algorithm>

#include "crypto.hpp"
#include "files.hpp"
#include "node_content.hpp"
#include "references.hpp"
#include "tlv.hpp"

namespace nw {

namespace {

Result<SymmetricKey> decodeFragment(std::string_view fragmentKey) {
  std::optional<Bytes> raw = fromBase64Url(fragmentKey);
  if (!raw.has_value() || raw->size() != kKeyBytes) {
    return Status::Malformed;
  }
  Result<SymmetricKey> key = SymmetricKey::fromBytes(*raw);
  sodium_memzero(raw->data(), raw->size());
  return key;
}

bool isLinked(const std::map<std::string, Node>& nodes, const std::string& nodeId) {
  return std::any_of(nodes.begin(), nodes.end(), [&](const auto& entry) {
    const std::vector<std::string>& links = entry.second.links;
    return std::find(links.begin(), links.end(), nodeId) != links.end();
  });
}

// Linked rows come with the link but live elsewhere.
std::string topLevelNodeId(const std::map<std::string, Node>& nodes) {
  std::string found;
  for (const auto& [id, node] : nodes) {
    bool topLevel = !node.parentId.has_value() || nodes.count(*node.parentId) == 0;
    topLevel = topLevel && !isLinked(nodes, id);
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
  Result<SymmetricKey> fragment = decodeFragment(fragmentKey);
  const Json* nodesJson = readArray(pullResponse, "nodes");
  if (!fragment.ok() || nodesJson == nullptr) {
    return Status::Malformed;
  }
  std::unique_ptr<LinkReader> reader(new LinkReader());
  LinkReader* self = reader.get();
  reader->keyring_.setLinkKeyLookup([self](const Node& target) { return self->keyThroughLinks(target); });
  for (const Json& entry : *nodesJson) {
    Result<Node> node = nodeFromJson(entry);
    if (node.ok() && validateNodeShape(node.value()) == Status::Ok) {
      std::string id = node.value().id;
      reader->nodes_[id] = node.take();
    }
  }
  reader->linkedNodeId_ = readString(pullResponse, "nodeId").value_or(topLevelNodeId(reader->nodes_));
  const Node* linked = reader->findNode(reader->linkedNodeId_);
  if (linked == nullptr) {
    return Status::NotFound;
  }
  reader->keyring_.addNodeKey(linked->id, fragment.take());
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

Status LinkReader::setDescriptor(const std::string& collection, std::string_view descriptorText,
                                 std::string_view schemaVersion) {
  std::optional<Semver> version = parseSemverText(schemaVersion);
  if (!version.has_value()) {
    return Status::InvalidArgument;
  }
  Result<std::shared_ptr<const SchemaDescriptor>> schema = parseDescriptor(descriptorText);
  if (!schema.ok()) {
    return schema.status();
  }
  registered_[collection] = RegisteredSchema{schema.take(), *version};
  return Status::Ok;
}

std::vector<DescriptorNeed> LinkReader::missingDescriptors() const {
  std::set<std::pair<std::string, std::string>> needed;
  for (const auto& [id, node] : nodes_) {
    auto registered = registered_.find(node.collection);
    if (registered == registered_.end() || node.deleted || !node.schemaVersion.has_value()) {
      continue;
    }
    std::optional<Semver> written = parseSemverText(*node.schemaVersion);
    bool held = published_.count(node.collection + " " + *node.schemaVersion) > 0;
    if (written.has_value() && *written < registered->second.version && !held) {
      needed.insert({node.collection, *node.schemaVersion});
    }
  }
  std::vector<DescriptorNeed> needs;
  for (const auto& [collection, version] : needed) {
    needs.push_back(DescriptorNeed{collection, version});
  }
  return needs;
}

Status LinkReader::acceptPublishedDescriptor(const DescriptorNeed& need, const std::string& descriptorHash,
                                             const Bytes& text) {
  if (toBase64Url(hash(text)) != descriptorHash) {
    return Status::AuthenticationFailed;
  }
  Result<std::shared_ptr<const SchemaDescriptor>> schema = parseDescriptor(std::string(text.begin(), text.end()));
  if (!schema.ok()) {
    return schema.status();
  }
  published_[need.collection + " " + need.version] = schema.take();
  return Status::Ok;
}

Result<const SchemaDescriptor*> LinkReader::schemaOfRow(const Node& node) const {
  auto registered = registered_.find(node.collection);
  if (registered == registered_.end()) {
    return Status::InvalidState;
  }
  if (!node.schemaVersion.has_value()) {
    return registered->second.schema.get();
  }
  std::optional<Semver> written = parseSemverText(*node.schemaVersion);
  if (!written.has_value()) {
    return Status::InvalidArgument;
  }
  if (*written == registered->second.version) {
    return registered->second.schema.get();
  }
  if (*written > registered->second.version) {
    return Status::Unsupported;
  }
  auto published = published_.find(node.collection + " " + *node.schemaVersion);
  if (published == published_.end()) {
    return Status::InvalidState;
  }
  return published->second.get();
}

Result<LinkReader::StoredContent> LinkReader::readStoredContent(const Node& node) {
  NodeLookup lookup = [this](const std::string& id) { return findNode(id); };
  FacetKeyResolver keyFor = [&](uint32_t tag) { return keyring_.resolveFacetKey(node, tag, lookup); };
  Result<const SchemaDescriptor*> schema = schemaOfRow(node);
  if (!schema.ok()) {
    return schema.status();
  }
  const TableDescriptor* table = schema.value()->tableByName(*node.table);
  if (table == nullptr) {
    return Status::InvalidState;
  }
  Result<FacetMap> readable = readableFacets(node, *table, keyFor);
  if (!readable.ok()) {
    return readable.status();
  }
  if (readable.value().empty()) {
    return Status::NotFound;
  }
  CodecError error;
  Result<Json> content = decodeContent(*table, readable.value(), error);
  if (!content.ok()) {
    return content.status();
  }
  if (checkNodeFiles(*table, node, content.value()) != Status::Ok) {
    return Status::IntegrityFailure;
  }
  return StoredContent{table, content.take()};
}

Result<SymmetricKey> LinkReader::keyThroughLinks(const Node& target) {
  if (!rowsResolvingThroughLinks_.insert(target.id).second) {
    return Status::NotFound;
  }
  Result<SymmetricKey> found = Status::NotFound;
  for (const auto& [id, linker] : nodes_) {
    bool links = std::find(linker.links.begin(), linker.links.end(), target.id) != linker.links.end();
    if (!links || linker.deleted) {
      continue;
    }
    Result<StoredContent> stored = readStoredContent(linker);
    if (stored.ok()) {
      found = findReferenceKey(*stored.value().table->model, stored.value().content, target.id);
    }
    if (found.ok()) {
      break;
    }
  }
  rowsResolvingThroughLinks_.erase(target.id);
  return found;
}

Result<Json> LinkReader::readNode(const std::string& nodeId) {
  const Node* node = findNode(nodeId);
  if (node == nullptr || node->deleted) {
    return Status::NotFound;
  }
  if (isRoot(*node)) {
    return Json::object();
  }
  Result<StoredContent> stored = readStoredContent(*node);
  if (!stored.ok()) {
    return stored.status();
  }
  const ModelDescriptor& model = *stored.value().table->model;
  removeFileKeys(model, stored.value().content);
  removeReferenceKeys(model, stored.value().content);
  return std::move(stored.value().content);
}

Result<SymmetricKey> LinkReader::resolveFileKey(const std::string& nodeId, const std::string& objectId) {
  const Node* node = findNode(nodeId);
  if (node == nullptr || node->deleted || isRoot(*node)) {
    return Status::NotFound;
  }
  Result<StoredContent> stored = readStoredContent(*node);
  if (!stored.ok()) {
    return stored.status();
  }
  return findFileKey(*stored.value().table->model, stored.value().content, objectId);
}

}  // namespace nw
