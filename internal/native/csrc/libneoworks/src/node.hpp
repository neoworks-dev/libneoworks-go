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
  // The row's table, by model name; absent on roots. Plain, so a reader picks the model before
  // decrypting.
  std::optional<std::string> table;
  std::optional<Bytes> wrappedKey;
  // A message with one LEN field per facet: key `tag * 8 + 2`, body the facet ciphertext.
  Bytes content;
  // Plain (unencrypted): the files in `content`, in the order the core collected them.
  std::vector<NodeFile> files;
  // Plain (unencrypted): the rows whose keys the references in `content` carry, ascending and
  // distinct. The server sends them to whoever can read this row.
  std::vector<std::string> links;
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
};

// A registry path, "@scope/name".
bool isValidCollection(std::string_view collection);
// "root" for a collection's root, which carries no content, or "row".
bool isValidKind(std::string_view kind);
// A model name: a letter or underscore, then letters, digits and underscores, at most 128 bytes.
bool isValidTable(std::string_view table);
bool isValidPrincipalType(std::string_view principalType);
bool isRoot(const Node& node);
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
// Malformed unless an array of distinct lowercase uuids in ascending order.
Result<std::vector<std::string>> linksFromJson(const Json& json);
// The bytes covered by H(links) in the write signature: empty for no links, otherwise the compact
// JSON array of the ids.
Bytes canonicalLinksBytes(const std::vector<std::string>& links);

Bytes nodeKeyWrapAad(std::string_view id, const std::optional<std::string>& parentId);
Bytes facetAad(std::string_view id, std::string_view collection, uint32_t tag, uint64_t baseSeq, bool deleted);
// Binds a chunk to its object, position and the final flag, not to a node, so a File value can
// move to another record with its stored objects.
Bytes blobChunkAad(std::string_view objectId, uint32_t index, bool finalChunk);

SymmetricKey facetKey(const SymmetricKey& nodeKey, uint32_t tag);
// The key of one stored object, the original or a variant of a file: BLAKE2b-256 keyed with the
// file's random key over "nwfile02" followed by the object id as lowercase hyphenated text.
SymmetricKey objectKey(const SymmetricKey& fileKey, std::string_view objectId);

Bytes wrapNodeKey(const SymmetricKey& parentKey, const SymmetricKey& nodeKey, std::string_view id,
                  const std::optional<std::string>& parentId);
Result<SymmetricKey> unwrapNodeKey(const SymmetricKey& parentKey, ByteView wrappedKey, std::string_view id,
                                   const std::optional<std::string>& parentId);

// pad then aead; the AAD binds the ciphertext to its node, facet and write.
Bytes encryptFacet(const SymmetricKey& facetKeyValue, std::string_view id, std::string_view collection,
                   uint32_t tag, uint64_t baseSeq, bool deleted, ByteView plaintext);
// NotFound when the content holds no facet with this tag.
Result<Bytes> decryptFacet(const SymmetricKey& facetKeyValue, const Node& node, uint32_t tag);
// Encrypts each facet under the node key for the node's current write and sets
// node.content.
void sealContent(Node& node, const SymmetricKey& nodeKey, const FacetMap& plaintexts);
// Every facet's plaintext; fails if any facet does not decrypt.
Result<FacetMap> openContent(const Node& node, const SymmetricKey& nodeKey);

size_t blobChunkCount(uint64_t size);
Bytes encryptBlobChunk(const SymmetricKey& objectKeyValue, std::string_view objectId, uint32_t index,
                       bool finalChunk, ByteView plaintext);
Result<Bytes> decryptBlobChunk(const SymmetricKey& objectKeyValue, std::string_view objectId, uint32_t index,
                               bool finalChunk, ByteView boxed);

// "nw-node-write-v4".
Bytes nodeWriteMessage(const Node& node);
// Sets node.signature.
Status signNodeWrite(ByteView signSecret, Node& node);
bool verifyNodeWrite(ByteView signPub, const Node& node);

}  // namespace nw
