#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "descriptor.hpp"
#include "keyring.hpp"

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
  // The descriptor rows of `collection` are read with. Malformed: not a valid descriptor.
  Status setDescriptor(const std::string& collection, std::string_view descriptorText);
  // The fields of the facets the link opens, as Client::readNode.
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
  Result<SymmetricKey> keyThroughLinks(const Node& target);

  std::map<std::string, Node> nodes_;
  std::map<std::string, std::shared_ptr<const SchemaDescriptor>> descriptors_;
  Keyring keyring_;
  std::string linkedNodeId_;
  std::set<std::string> rowsResolvingThroughLinks_;
};

}  // namespace nw
