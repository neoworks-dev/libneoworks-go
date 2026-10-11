#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "descriptor.hpp"
#include "keyring.hpp"

namespace nw {

// Read-only view of a link share for someone without an account. The only key
// material is the URL fragment: base64url(u32be epoch || node key) of the linked node.
class LinkReader {
 public:
  // pullResponse: {"nodeId"?: id, "nodes": [...]}. Without nodeId the single node
  // whose parent is not part of the response is taken as the linked node.
  static Result<std::unique_ptr<LinkReader>> open(const Json& pullResponse, std::string_view fragmentKey);

  const std::string& linkedNodeId() const { return linkedNodeId_; }
  std::vector<std::string> nodeIds() const;
  const Node* findNode(const std::string& nodeId) const;
  // The descriptor nodes of `collection` are read with. Malformed: not a valid descriptor.
  Status setDescriptor(const std::string& collection, std::string_view descriptorText);
  // The fields of the facets the link opens, as Client::readNode.
  Result<Json> readNode(const std::string& nodeId);
  Result<SymmetricKey> resolveNodeKey(const std::string& nodeId);

 private:
  LinkReader() = default;

  std::map<std::string, Node> nodes_;
  std::map<std::string, std::shared_ptr<const SchemaDescriptor>> descriptors_;
  Keyring keyring_;
  std::string linkedNodeId_;
};

}  // namespace nw
