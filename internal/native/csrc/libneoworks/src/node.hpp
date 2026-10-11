#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "json.hpp"

namespace nw {

constexpr size_t kBlobChunkBytes = size_t{4} * 1024 * 1024;
constexpr uint64_t kBlobKeyIdBase = 65536;

struct BlobVariant {
  std::string name;
  std::string objectId;
  uint32_t chunks = 0;
  uint64_t size = 0;
};

struct BlobDescriptor {
  std::string objectId;
  uint32_t chunks = 0;
  uint64_t size = 0;
  std::vector<BlobVariant> variants;
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
  std::optional<BlobDescriptor> blob;
  // Set together on shortcuts only: the item the shortcut opens and the most it grants.
  std::optional<std::string> targetId;
  std::optional<std::string> targetRole;
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
// The kind of the descriptor model that describes a node's content: an item that carries a file
// is an asset, every other node is described by the model of its own kind.
std::string contentKindFor(std::string_view kind, bool carriesFile);
std::string contentKindOf(const Node& node);

// Malformed unless the content is LEN fields with ascending, unique facet tags.
Result<FacetMap> parseContent(ByteView content);
Bytes assembleContent(const FacetMap& ciphertexts);

Json nodeToJson(const Node& node);
Result<Node> nodeFromJson(const Json& json);
// Structural invariants independent of any key material.
Status validateNodeShape(const Node& node);

Json blobToJson(const BlobDescriptor& blob);
Result<BlobDescriptor> blobFromJson(const Json& json);
// The bytes covered by H(blob) in the write signature: compact JSON with keys in contract order.
Bytes canonicalBlobBytes(const BlobDescriptor& blob);

Bytes nodeKeyWrapAad(std::string_view id, const std::optional<std::string>& parentId, uint32_t epoch,
                     uint32_t parentEpoch);
Bytes facetAad(std::string_view id, std::string_view collection, uint32_t tag, uint32_t epoch, uint64_t baseSeq,
               bool deleted);
Bytes blobChunkAad(std::string_view id, std::string_view objectId, uint32_t index, bool finalChunk);

SymmetricKey facetKey(const SymmetricKey& nodeKey, uint32_t tag);
SymmetricKey blobKey(const SymmetricKey& nodeKey, uint32_t variantIndex);

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
Bytes encryptBlobChunk(const SymmetricKey& blobKeyValue, std::string_view nodeId, std::string_view objectId,
                       uint32_t index, bool finalChunk, ByteView plaintext);
Result<Bytes> decryptBlobChunk(const SymmetricKey& blobKeyValue, std::string_view nodeId,
                               std::string_view objectId, uint32_t index, bool finalChunk, ByteView boxed);

Bytes nodeWriteMessage(const Node& node);
// Sets node.signature.
Status signNodeWrite(ByteView signSecret, Node& node);
bool verifyNodeWrite(ByteView signPub, const Node& node);

}  // namespace nw
