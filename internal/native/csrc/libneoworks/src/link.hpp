#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "descriptor.hpp"
#include "keyring.hpp"
#include "semver.hpp"

namespace nw {

// Read-only view of a link share for someone without an account. The only key
// material is the URL fragment: base64url(node key) of the linked row; the rows
// belonging to it open through it, and the rows they link to through those links.
class LinkReader {
 public:
  // pullResponse: {"nodeId"?: id, "nodes": [...]}. Without nodeId the single row whose parent is
  // not part of the response and that no other row links to is taken as the linked row.
  static Result<std::unique_ptr<LinkReader>> open(const Json& pullResponse, std::string_view fragmentKey);

  const std::string& linkedNodeId() const { return linkedNodeId_; }
  std::vector<std::string> nodeIds() const;
  const Node* findNode(const std::string& nodeId) const;
  // The descriptor of `collection` at `schemaVersion`, the version of the app reading: rows written
  // at that version, and rows that record none, are read with it. Malformed: not a valid
  // descriptor. InvalidArgument: not a valid version.
  Status setDescriptor(const std::string& collection, std::string_view descriptorText, std::string_view schemaVersion);
  // The versions below the app's that rows of the registered collections were written at, whose
  // descriptors are not held yet. Rows are read with the descriptor of the version that wrote them;
  // fetch each from the registry by the hash it publishes for the version and hand it to
  // acceptPublishedDescriptor.
  std::vector<DescriptorNeed> missingDescriptors() const;
  // Keeps the descriptor of a published version once `text` is exactly the descriptor with the hash
  // the registry publishes for it. AuthenticationFailed: the hash differs. Malformed: not a valid
  // descriptor.
  Status acceptPublishedDescriptor(const DescriptorNeed& need, const std::string& descriptorHash, const Bytes& text);
  // The fields of the facets the link opens, as Client::readNode. Unsupported: the row was written
  // at a version above the app's. InvalidState: the descriptor of the row's version is not held yet.
  Result<Json> readNode(const std::string& nodeId);
  Result<SymmetricKey> resolveNodeKey(const std::string& nodeId);
  // The key of the file that has the object `objectId`, read from the File values of the fields
  // the link opens, as Client::resolveFileKey.
  Result<SymmetricKey> resolveFileKey(const std::string& nodeId, const std::string& objectId);

 private:
  LinkReader() = default;
  // The fields of the facets the link opens, Files and references with their keys, and the table
  // the row names.
  struct StoredContent {
    const TableDescriptor* table = nullptr;
    Json content;
  };
  Result<StoredContent> readStoredContent(const Node& node);
  // The schema a row is read with: the app's for a row written at its version, the fetched one for a
  // row written below it.
  Result<const SchemaDescriptor*> schemaOfRow(const Node& node) const;
  Result<SymmetricKey> keyThroughLinks(const Node& target);

  std::map<std::string, Node> nodes_;
  struct RegisteredSchema {
    std::shared_ptr<const SchemaDescriptor> schema;
    Semver version;
  };
  std::map<std::string, RegisteredSchema> registered_;
  // The descriptors of earlier published versions, by "<collection> <version>".
  std::map<std::string, std::shared_ptr<const SchemaDescriptor>> published_;
  Keyring keyring_;
  std::string linkedNodeId_;
  std::set<std::string> rowsResolvingThroughLinks_;
};

}  // namespace nw
