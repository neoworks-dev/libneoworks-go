#include <algorithm>

#include "client.hpp"
#include "node_content.hpp"
#include "semver.hpp"

namespace nw {

namespace {

std::string versionKey(const std::string& collection, const std::string& version) {
  return collection + " " + version;
}

std::string schemaPath(const std::string& collection) {
  size_t slash = collection.find('/');
  return "/api/v1/schemas/" + collection.substr(1, slash - 1) + "/" + collection.substr(slash + 1);
}

std::string textOf(const Bytes& bytes) { return std::string(bytes.begin(), bytes.end()); }

bool isLiveRowOf(const Node& node, const std::string& table) {
  return !isRoot(node) && !node.deleted && node.table.has_value() && *node.table == table;
}

bool isWrittenBelow(const Node& node, const Semver& version) {
  if (!node.schemaVersion.has_value()) {
    return false;
  }
  std::optional<Semver> written = parseSemverText(*node.schemaVersion);
  return written.has_value() && *written < version;
}

}  // namespace

HttpRequest schemaRecordRequest(const std::string& collection) {
  HttpRequest request;
  request.method = "GET";
  request.url = schemaPath(collection);
  return request;
}

HttpRequest descriptorRequest(const std::string& collection, const std::string& descriptorHash) {
  HttpRequest request;
  request.method = "GET";
  request.url = schemaPath(collection) + "/descriptors/" + descriptorHash;
  return request;
}

const std::string& Client::registeredVersion(const std::string& collection) const {
  return descriptors_.at(collection).schemaVersion;
}

void Client::stampSchemaVersion(Node& node, const std::string& version) { node.schemaVersion = version; }

// ── Schemas by version ────────────────────────────────────────────────────────

Result<const SchemaDescriptor*> Client::schemaOfRow(const Node& node) {
  const SchemaDescriptor* registered = descriptorFor(node.collection);
  if (registered == nullptr) {
    lastContentError_ = contentError(Status::InvalidState, node.collection, "no confirmed descriptor for the collection");
    return Status::InvalidState;
  }
  if (!node.schemaVersion.has_value()) {
    return registered;
  }
  return schemaAtVersion(node.collection, *node.schemaVersion);
}

Result<const SchemaDescriptor*> Client::schemaAtVersion(const std::string& collection, const std::string& version) {
  const std::string& registered = registeredVersion(collection);
  std::optional<Semver> requested = parseSemverText(version);
  if (!requested.has_value()) {
    lastContentError_ = contentError(Status::InvalidArgument, collection, version + " is not a schema version");
    return Status::InvalidArgument;
  }
  Semver current = *parseSemverText(registered);
  if (*requested == current) {
    return descriptors_.at(collection).schema.get();
  }
  if (*requested > current) {
    lastContentError_ = contentError(Status::Unsupported, collection,
                                     "written at schema version " + version + ", above this app's " + registered);
    return Status::Unsupported;
  }
  return publishedSchema(collection, version);
}

Result<const SchemaDescriptor*> Client::publishedSchema(const std::string& collection, const std::string& version) {
  std::string key = versionKey(collection, version);
  auto cached = publishedSchemas_.find(key);
  if (cached != publishedSchemas_.end()) {
    return cached->second.get();
  }
  const LocalDatabase::PublishedDescriptor* stored = database_->findPublishedDescriptor(collection, version);
  if (stored == nullptr) {
    lastContentError_ = contentError(Status::InvalidState, collection,
                                     "the descriptor of schema version " + version + " is not loaded yet");
    return Status::InvalidState;
  }
  Result<std::shared_ptr<const SchemaDescriptor>> parsed = parseDescriptor(textOf(stored->text));
  if (!parsed.ok()) {
    return parsed.status();
  }
  publishedSchemas_[key] = parsed.take();
  return publishedSchemas_[key].get();
}

Result<const TableDescriptor*> Client::tableIn(const SchemaDescriptor& schema, const std::string& collection,
                                               const std::string& table) {
  const TableDescriptor* found = schema.tableByName(table);
  if (found == nullptr) {
    lastContentError_ = contentError(Status::InvalidArgument, collection, "the schema has no table " + table);
    return Status::InvalidArgument;
  }
  return found;
}

Result<const TableDescriptor*> Client::tableOfRow(const Node& node) {
  Result<const SchemaDescriptor*> schema = schemaOfRow(node);
  if (!schema.ok()) {
    return schema.status();
  }
  return tableIn(*schema.value(), node.collection, *node.table);
}

bool Client::sharesFieldsWithRegistered(const Node& node) const {
  auto registered = descriptors_.find(node.collection);
  if (registered == descriptors_.end() || !node.schemaVersion.has_value()) {
    return true;
  }
  std::optional<Semver> written = parseSemverText(*node.schemaVersion);
  Semver current = *parseSemverText(registered->second.schemaVersion);
  return written.has_value() && *written <= current && compatibilityLine(*written) == compatibilityLine(current);
}

bool Client::isOnEarlierLine(const Node& node) const {
  auto registered = descriptors_.find(node.collection);
  if (registered == descriptors_.end() || !node.schemaVersion.has_value()) {
    return false;
  }
  std::optional<Semver> written = parseSemverText(*node.schemaVersion);
  Semver current = *parseSemverText(registered->second.schemaVersion);
  return written.has_value() && *written < current && compatibilityLine(*written) != compatibilityLine(current);
}

// ── Fetching descriptors of earlier versions ──────────────────────────────────

std::set<std::string> Client::versionsBelowRegistered(const std::string& collection) const {
  Semver current = *parseSemverText(registeredVersion(collection));
  std::set<std::string> versions;
  for (const std::string& nodeId : database_->nodesInCollection(collection)) {
    const Node* node = database_->findNode(nodeId);
    if (!node->deleted && isWrittenBelow(*node, current)) {
      versions.insert(*node->schemaVersion);
    }
  }
  return versions;
}

std::vector<DescriptorNeed> Client::missingDescriptors() {
  std::vector<DescriptorNeed> needs;
  for (const auto& [collection, registered] : descriptors_) {
    for (const std::string& version : versionsBelowRegistered(collection)) {
      if (database_->findPublishedDescriptor(collection, version) == nullptr) {
        needs.push_back(DescriptorNeed{collection, version});
      }
    }
  }
  return needs;
}

Result<std::string> Client::descriptorText(const std::string& collection, const std::string& version) const {
  auto registered = descriptors_.find(collection);
  if (registered != descriptors_.end() && registered->second.schemaVersion == version) {
    return textOf(registered->second.text);
  }
  const LocalDatabase::PublishedDescriptor* published = database_->findPublishedDescriptor(collection, version);
  if (published == nullptr) {
    return Status::NotFound;
  }
  return textOf(published->text);
}

Status Client::acceptPublishedDescriptor(const DescriptorNeed& need, const std::string& descriptorHash,
                                         const Bytes& text) {
  if (toBase64Url(hash(text)) != descriptorHash) {
    return Status::AuthenticationFailed;
  }
  Result<std::shared_ptr<const SchemaDescriptor>> parsed = parseDescriptor(textOf(text));
  if (!parsed.ok()) {
    return parsed.status();
  }
  Status stored = database_->putPublishedDescriptor(need.collection, need.version,
                                                    LocalDatabase::PublishedDescriptor{descriptorHash, text});
  if (stored != Status::Ok) {
    return stored;
  }
  publishedSchemas_[versionKey(need.collection, need.version)] = parsed.take();
  indexPendingNodes();
  return Status::Ok;
}

// ── Rows by version ───────────────────────────────────────────────────────────

Result<std::vector<RowReference>> Client::rowsBelow(const std::string& collection, const std::string& table,
                                                    const std::string& version) const {
  std::optional<Semver> target = parseSemverText(version);
  if (!target.has_value()) {
    return Status::InvalidArgument;
  }
  std::vector<RowReference> rows;
  for (const std::string& nodeId : database_->nodesInCollection(collection)) {
    const Node* node = database_->findNode(nodeId);
    if (isLiveRowOf(*node, table) && isWrittenBelow(*node, *target)) {
      rows.push_back(RowReference{nodeId, *node->schemaVersion});
    }
  }
  return rows;
}

Result<RowRead> Client::readRow(const std::string& nodeId) {
  const Node* node = database_->findNode(nodeId);
  if (node == nullptr || node->deleted) {
    return Status::NotFound;
  }
  Result<Json> content = readContent(*node, nullptr);
  if (!content.ok()) {
    return content.status();
  }
  return RowRead{node->schemaVersion, content.take()};
}

// ── Updates across versions ───────────────────────────────────────────────────

Result<Client::UpdatePlan> Client::planUpdate(const Node& node, const UpdateNodeRequest& request) {
  Result<const TableDescriptor*> storedTable = tableOfRow(node);
  if (!storedTable.ok()) {
    return storedTable.status();
  }
  const std::string& registered = registeredVersion(node.collection);
  bool atRegistered = !node.schemaVersion.has_value() || *node.schemaVersion == registered;
  if (!request.schemaVersion.has_value() && !atRegistered) {
    lastContentError_ = contentError(Status::InvalidState, node.id,
                                     "the row is at schema version " + *node.schemaVersion + "; write it at version " +
                                         registered + " to migrate it");
    return Status::InvalidState;
  }
  if (!request.schemaVersion.has_value() || *request.schemaVersion == node.schemaVersion) {
    return UpdatePlan{storedTable.value(), storedTable.value(), registered, false};
  }
  return planMigration(node, *storedTable.value(), *request.schemaVersion);
}

Result<Client::UpdatePlan> Client::planMigration(const Node& node, const TableDescriptor& storedTable,
                                                 const std::string& target) {
  std::optional<Semver> targetVersion = parseSemverText(target);
  if (!targetVersion.has_value()) {
    lastContentError_ = contentError(Status::InvalidArgument, node.id, target + " is not a schema version");
    return Status::InvalidArgument;
  }
  if (node.schemaVersion.has_value() && *targetVersion < *parseSemverText(*node.schemaVersion)) {
    lastContentError_ = contentError(Status::InvalidArgument, node.id, "a row does not move to an earlier schema version");
    return Status::InvalidArgument;
  }
  Result<const SchemaDescriptor*> schema = schemaAtVersion(node.collection, target);
  if (!schema.ok()) {
    return schema.status();
  }
  Result<const TableDescriptor*> writeTable = tableIn(*schema.value(), node.collection, *node.table);
  if (!writeTable.ok()) {
    return writeTable.status();
  }
  return UpdatePlan{&storedTable, writeTable.value(), target, true};
}

Result<FacetMap> Client::updatedPlaintexts(const UpdatePlan& plan, const UpdateNodeRequest& request,
                                           const FacetMap& previous) {
  Result<Json> keyed = withKeys(*plan.writeTable, *plan.storedTable, request.changes, previous);
  if (!keyed.ok()) {
    return keyed.status();
  }
  FacetMap base;
  if (!plan.migrates) {
    base = previous;
  }
  return encodeContent(*plan.writeTable, keyed.value(), base, !plan.migrates, lastContentError_);
}

}  // namespace nw
