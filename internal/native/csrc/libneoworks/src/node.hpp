#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "json.hpp"

namespace nw {

constexpr size_t kBlobChunkBytes = size_t{4} * 1024 * 1024;

// One stored file of a node, as the server sees it: the storage object and what it takes, with
// no name. A node lists the original and every variant of every `File` in its content.
struct NodeFile {
  std::string objectId;
  uint32_t chunks = 0;
  uint64_t size = 0;

  bool operator==(const NodeFile& other) const = default;
};

// The facets of a node's content: tag to ciphertext, or tag to plaintext once opened.
using FacetMap = std::map<uint32_t, Bytes>;

struct Node {
  std::string id;
  std::optional<std::string> parentId;
  std::string ownerId;
  std::string collection;
  std::string kind;
  uint32_t epoch = 0;
  std::optional<Bytes> wrappedKey;
  // A message with one LEN field per facet: key `tag * 8 + 2`, body the facet ciphertext.
  Bytes content;
  // Plain (unencrypted): the files in `content`, in the order the core collected them.
  std::vector<NodeFile> files;
  // Set together on shortcuts only: the item the shortcut opens and the most it grants.
  std::optional<std::string> targetId;
  std::optional<std::string> targetRole;
  // Plain and signed: the collection's schema version that encoded `content`, "major.minor.patch".
  // Absent on roots, and on nodes the core wrote before it carried one.
  std::optional<std::string> schemaVersion;
  bool deleted = false;
  uint64_t baseSeq = 0;
  uint64_t seq = 0;
  std::string authorType;
  std::string authorId;
  std::optional<std::string> certId;
  Bytes signature;
  std::string createdAt;
  std::string updatedAt;
  // Server advisory (an install was revoked); not covered by the write signature.
  bool needsRotation = false;
};

// A registry path, "@scope/name".
bool isValidCollection(std::string_view collection);
bool isValidKind(std::string_view kind);
bool isValidPrincipalType(std::string_view principalType);
bool isShortcut(const Node& node);
// Malformed unless the content is LEN fields with ascending, unique facet tags.
Result<FacetMap> parseContent(ByteView content);
Bytes assembleContent(const FacetMap& ciphertexts);

Json nodeToJson(const Node& node);
Result<Node> nodeFromJson(const Json& json);
// Structural invariants independent of any key material.
Status validateNodeShape(const Node& node);

Json filesToJson(const std::vector<NodeFile>& files);
// Malformed unless an array of {objectId, chunks, size} with distinct lowercase uuids.
Result<std::vector<NodeFile>> filesFromJson(const Json& json);
// The bytes covered by H(files) in the write signature: empty for no files, otherwise the compact
// JSON array with keys in contract order.
Bytes canonicalFilesBytes(const std::vector<NodeFile>& files);

Bytes nodeKeyWrapAad(std::string_view id, const std::optional<std::string>& parentId, uint32_t epoch,
                     uint32_t parentEpoch);
Bytes facetAad(std::string_view id, std::string_view collection, uint32_t tag, uint32_t epoch, uint64_t baseSeq,
               bool deleted);
// Binds a chunk to its object, position and the final flag, not to a node, so a File value can
// move to another record with its stored objects.
Bytes blobChunkAad(std::string_view objectId, uint32_t index, bool finalChunk);

SymmetricKey facetKey(const SymmetricKey& nodeKey, uint32_t tag);
// The key of one stored object, the original or a variant of a file: BLAKE2b-256 keyed with the
// file's random key over "nwfile02" followed by the object id as lowercase hyphenated text.
SymmetricKey objectKey(const SymmetricKey& fileKey, std::string_view objectId);

Bytes wrapNodeKey(const SymmetricKey& parentKey, const SymmetricKey& nodeKey, std::string_view id,
                  const std::optional<std::string>& parentId, uint32_t epoch, uint32_t parentEpoch);
Result<SymmetricKey> unwrapNodeKey(const SymmetricKey& parentKey, ByteView wrappedKey, std::string_view id,
                                   const std::optional<std::string>& parentId, uint32_t epoch,
                                   uint32_t parentEpoch);

// pad then aead; the AAD binds the ciphertext to its node, facet, epoch and write.
Bytes encryptFacet(const SymmetricKey& facetKeyValue, std::string_view id, std::string_view collection,
                   uint32_t tag, uint32_t epoch, uint64_t baseSeq, bool deleted, ByteView plaintext);
// NotFound when the content holds no facet with this tag.
Result<Bytes> decryptFacet(const SymmetricKey& facetKeyValue, const Node& node, uint32_t tag);
// Encrypts each facet under the node key for the node's current epoch and write and sets
// node.content.
void sealContent(Node& node, const SymmetricKey& nodeKey, const FacetMap& plaintexts);
// Every facet's plaintext; fails if any facet does not decrypt.
Result<FacetMap> openContent(const Node& node, const SymmetricKey& nodeKey);

size_t blobChunkCount(uint64_t size);
Bytes encryptBlobChunk(const SymmetricKey& objectKeyValue, std::string_view objectId, uint32_t index,
                       bool finalChunk, ByteView plaintext);
Result<Bytes> decryptBlobChunk(const SymmetricKey& objectKeyValue, std::string_view objectId, uint32_t index,
                               bool finalChunk, ByteView boxed);

// "nw-node-write-v4" when the node carries a schema version, else "nw-node-write-v3".
Bytes nodeWriteMessage(const Node& node);
// Sets node.signature.
Status signNodeWrite(ByteView signSecret, Node& node);
bool verifyNodeWrite(ByteView signPub, const Node& node);

}  // namespace nw
