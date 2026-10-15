#include "node.hpp"

#include <algorithm>
#include <set>

#include "tlv.hpp"
#include "wire.hpp"

namespace nw {

namespace {

constexpr std::string_view kFacetContext = "nwfacet1";
constexpr std::string_view kFileKeyContext = "nwfile01";
constexpr std::string_view kKinds[] = {"root", "container", "item"};
constexpr std::string_view kPrincipalTypes[] = {"user", "install"};
constexpr std::string_view kTargetRoles[] = {"read", "write"};
constexpr size_t kMaxRegistrySegment = 64;

template <size_t Count>
bool isOneOf(const std::string_view (&allowed)[Count], std::string_view candidate) {
  return std::find(std::begin(allowed), std::end(allowed), candidate) != std::end(allowed);
}

// A registry scope or name: [a-z0-9][a-z0-9._-]{0,63}.
bool isRegistrySegment(std::string_view segment) {
  if (segment.empty() || segment.size() > kMaxRegistrySegment) {
    return false;
  }
  auto allowed = [](char character) {
    bool lowerOrDigit = (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9');
    return lowerOrDigit || character == '.' || character == '_' || character == '-';
  };
  bool leadsWell = allowed(segment.front()) && segment.front() != '.' && segment.front() != '_' &&
                   segment.front() != '-';
  return leadsWell && std::all_of(segment.begin(), segment.end(), allowed);
}

}  // namespace

bool isValidCollection(std::string_view collection) {
  size_t slash = collection.find('/');
  if (collection.empty() || collection.front() != '@' || slash == std::string_view::npos) {
    return false;
  }
  return isRegistrySegment(collection.substr(1, slash - 1)) && isRegistrySegment(collection.substr(slash + 1));
}

bool isValidKind(std::string_view kind) { return isOneOf(kKinds, kind); }
bool isValidPrincipalType(std::string_view principalType) { return isOneOf(kPrincipalTypes, principalType); }
bool isShortcut(const Node& node) { return node.targetId.has_value(); }

Result<FacetMap> parseContent(ByteView content) {
  FacetMap facets;
  wire::Reader reader(content);
  uint32_t previousTag = 0;
  while (!reader.atEnd()) {
    wire::Field field;
    if (reader.next(field) != Status::Ok || field.type != wire::WireType::Len || field.ordinal <= previousTag) {
      return Status::Malformed;
    }
    facets.emplace(field.ordinal, Bytes(field.body.begin(), field.body.end()));
    previousTag = field.ordinal;
  }
  return facets;
}

Bytes assembleContent(const FacetMap& ciphertexts) {
  wire::Writer writer;
  for (const auto& [tag, ciphertext] : ciphertexts) {
    writer.key(tag, wire::WireType::Len);
    writer.lengthDelimited(ciphertext);
  }
  return writer.take();
}

Json filesToJson(const std::vector<NodeFile>& files) {
  Json list = Json::array();
  for (const NodeFile& file : files) {
    Json entry = Json::object();
    entry["objectId"] = file.objectId;
    entry["chunks"] = file.chunks;
    entry["size"] = file.size;
    list.push_back(std::move(entry));
  }
  return list;
}

namespace {

Result<NodeFile> fileFromJson(const Json& json) {
  std::optional<std::string> objectId = readString(json, "objectId");
  std::optional<uint64_t> chunks = readUnsigned(json, "chunks");
  std::optional<uint64_t> size = readUnsigned(json, "size");
  if (!objectId || !chunks || !size || *chunks > UINT32_MAX || !isLowercaseUuid(*objectId)) {
    return Status::Malformed;
  }
  return NodeFile{*objectId, static_cast<uint32_t>(*chunks), *size};
}

}  // namespace

Result<std::vector<NodeFile>> filesFromJson(const Json& json) {
  if (!json.is_array()) {
    return Status::Malformed;
  }
  std::vector<NodeFile> files;
  std::set<std::string> objectIds;
  for (const Json& entry : json) {
    Result<NodeFile> file = fileFromJson(entry);
    if (!file.ok() || !objectIds.insert(file.value().objectId).second) {
      return Status::Malformed;
    }
    files.push_back(file.take());
  }
  return files;
}

Bytes canonicalFilesBytes(const std::vector<NodeFile>& files) {
  if (files.empty()) {
    return Bytes();
  }
  return bytesOf(dumpCompact(filesToJson(files)));
}

Json nodeToJson(const Node& node) {
  Json json = Json::object();
  json["id"] = node.id;
  json["parentId"] = Json(nullptr);
  if (node.parentId.has_value()) {
    json["parentId"] = *node.parentId;
  }
  json["ownerId"] = node.ownerId;
  json["collection"] = node.collection;
  json["kind"] = node.kind;
  json["epoch"] = node.epoch;
  json["wrappedKey"] = Json(nullptr);
  if (node.wrappedKey.has_value()) {
    json["wrappedKey"] = bytesToJson(*node.wrappedKey);
  }
  json["content"] = toBase64Url(node.content);
  json["files"] = filesToJson(node.files);
  json["targetId"] = Json(nullptr);
  json["targetRole"] = Json(nullptr);
  if (node.targetId.has_value()) {
    json["targetId"] = *node.targetId;
  }
  if (node.targetRole.has_value()) {
    json["targetRole"] = *node.targetRole;
  }
  json["deleted"] = node.deleted;
  json["baseSeq"] = node.baseSeq;
  json["seq"] = node.seq;
  json["authorType"] = node.authorType;
  json["authorId"] = node.authorId;
  json["certId"] = Json(nullptr);
  if (node.certId.has_value()) {
    json["certId"] = *node.certId;
  }
  json["signature"] = bytesToJson(node.signature);
  json["createdAt"] = node.createdAt;
  json["updatedAt"] = node.updatedAt;
  if (node.needsRotation) {
    json["needsRotation"] = true;
  }
  return json;
}

namespace {

struct NodeScalars {
  std::optional<std::string> id, ownerId, collection, kind, authorType, authorId, createdAt, updatedAt;
  std::optional<uint64_t> epoch, baseSeq, seq;
  std::optional<bool> deleted;
  std::optional<Bytes> signature;
  std::optional<Bytes> content;

  bool complete() const {
    return id && ownerId && collection && kind && authorType && authorId && createdAt && updatedAt && epoch &&
           baseSeq && seq && deleted && signature && content;
  }
};

NodeScalars readNodeScalars(const Json& json) {
  NodeScalars scalars;
  scalars.id = readString(json, "id");
  scalars.ownerId = readString(json, "ownerId");
  scalars.collection = readString(json, "collection");
  scalars.kind = readString(json, "kind");
  scalars.authorType = readString(json, "authorType");
  scalars.authorId = readString(json, "authorId");
  scalars.createdAt = readString(json, "createdAt");
  scalars.updatedAt = readString(json, "updatedAt");
  scalars.epoch = readUnsigned(json, "epoch");
  scalars.baseSeq = readUnsigned(json, "baseSeq");
  scalars.seq = readUnsigned(json, "seq");
  scalars.deleted = readBool(json, "deleted");
  scalars.signature = readBytes(json, "signature");
  scalars.content = readBytes(json, "content");
  return scalars;
}

}  // namespace

Result<Node> nodeFromJson(const Json& json) {
  NodeScalars scalars = readNodeScalars(json);
  if (!scalars.complete() || *scalars.epoch > UINT32_MAX) {
    return Status::Malformed;
  }
  bool wellFormed = true;
  Node node;
  node.parentId = readOptionalString(json, "parentId", wellFormed);
  node.wrappedKey = readOptionalBytes(json, "wrappedKey", wellFormed);
  node.certId = readOptionalString(json, "certId", wellFormed);
  node.targetId = readOptionalString(json, "targetId", wellFormed);
  node.targetRole = readOptionalString(json, "targetRole", wellFormed);
  if (!wellFormed) {
    return Status::Malformed;
  }
  node.content = std::move(*scalars.content);
  Json filesJson = Json::array();
  if (json.contains("files")) {
    filesJson = json.at("files");
  }
  Result<std::vector<NodeFile>> files = filesFromJson(filesJson);
  if (!files.ok()) {
    return files.status();
  }
  node.files = files.take();
  node.id = *scalars.id;
  node.ownerId = *scalars.ownerId;
  node.collection = *scalars.collection;
  node.kind = *scalars.kind;
  node.epoch = static_cast<uint32_t>(*scalars.epoch);
  node.deleted = *scalars.deleted;
  node.baseSeq = *scalars.baseSeq;
  node.seq = *scalars.seq;
  node.authorType = *scalars.authorType;
  node.authorId = *scalars.authorId;
  node.signature = std::move(*scalars.signature);
  node.createdAt = *scalars.createdAt;
  node.updatedAt = *scalars.updatedAt;
  node.needsRotation = readBool(json, "needsRotation").value_or(false);
  return node;
}

namespace {

bool hasValidIdentifiers(const Node& node) {
  if (!isLowercaseUuid(node.id) || !isLowercaseUuid(node.ownerId) || !isLowercaseUuid(node.authorId)) {
    return false;
  }
  if (node.parentId.has_value() && !isLowercaseUuid(*node.parentId)) {
    return false;
  }
  bool validTarget = !node.targetId.has_value() || isLowercaseUuid(*node.targetId);
  return validTarget && (!node.certId.has_value() || isLowercaseUuid(*node.certId));
}

bool hasValidParentage(const Node& node) {
  bool isRoot = node.kind == "root";
  if (isRoot) {
    return !node.parentId.has_value() && !node.wrappedKey.has_value() && node.content.empty();
  }
  return node.parentId.has_value() && node.wrappedKey.has_value();
}

// Shortcuts are items with no content or files of their own, pointing at another node.
bool hasValidShortcut(const Node& node) {
  if (node.targetId.has_value() != node.targetRole.has_value()) {
    return false;
  }
  if (!node.targetId.has_value()) {
    return true;
  }
  return node.kind == "item" && isOneOf(kTargetRoles, *node.targetRole) && *node.targetId != node.id &&
         node.content.empty() && node.files.empty();
}

bool hasValidAuthor(const Node& node) {
  if (node.authorType == "user") {
    return !node.certId.has_value();
  }
  return node.authorType == "install" && node.certId.has_value();
}

}  // namespace

Status validateNodeShape(const Node& node) {
  bool structurallyValid = isValidCollection(node.collection) && isValidKind(node.kind) && node.epoch >= 1 &&
                           hasValidIdentifiers(node) && hasValidParentage(node) && hasValidShortcut(node) &&
                           parseContent(node.content).ok() && hasValidAuthor(node);
  if (!structurallyValid) {
    return Status::Malformed;
  }
  return Status::Ok;
}

Bytes nodeKeyWrapAad(std::string_view id, const std::optional<std::string>& parentId, uint32_t epoch,
                     uint32_t parentEpoch) {
  return TlvWriter("nw-node-key-v1").text(id).optionalText(parentId).u32(epoch).u32(parentEpoch).finish();
}

Bytes facetAad(std::string_view id, std::string_view collection, uint32_t tag, uint32_t epoch, uint64_t baseSeq,
               bool deleted) {
  return TlvWriter("nw-node-content-v2")
      .text(id)
      .text(collection)
      .u32(tag)
      .u32(epoch)
      .u64(baseSeq)
      .flag(deleted)
      .finish();
}

Bytes blobChunkAad(std::string_view id, std::string_view objectId, uint32_t index, bool finalChunk) {
  return TlvWriter("nw-blob-chunk-v1").text(id).text(objectId).u32(index).flag(finalChunk).finish();
}

SymmetricKey facetKey(const SymmetricKey& nodeKey, uint32_t tag) { return kdf(nodeKey, tag, kFacetContext); }

SymmetricKey fileKey(const SymmetricKey& nodeKey, std::string_view objectId) {
  Bytes input = bytesOf(kFileKeyContext);
  Bytes id = bytesOf(objectId);
  input.insert(input.end(), id.begin(), id.end());
  return keyedHash(nodeKey, input);
}

Bytes wrapNodeKey(const SymmetricKey& parentKey, const SymmetricKey& nodeKey, std::string_view id,
                  const std::optional<std::string>& parentId, uint32_t epoch, uint32_t parentEpoch) {
  return aeadEncrypt(parentKey, nodeKey.view(), nodeKeyWrapAad(id, parentId, epoch, parentEpoch));
}

Result<SymmetricKey> unwrapNodeKey(const SymmetricKey& parentKey, ByteView wrappedKey, std::string_view id,
                                   const std::optional<std::string>& parentId, uint32_t epoch,
                                   uint32_t parentEpoch) {
  return aeadDecryptKey(parentKey, wrappedKey, nodeKeyWrapAad(id, parentId, epoch, parentEpoch));
}

Bytes encryptFacet(const SymmetricKey& facetKeyValue, std::string_view id, std::string_view collection,
                   uint32_t tag, uint32_t epoch, uint64_t baseSeq, bool deleted, ByteView plaintext) {
  Bytes associatedData = facetAad(id, collection, tag, epoch, baseSeq, deleted);
  return aeadEncrypt(facetKeyValue, pad(plaintext), associatedData);
}

Result<Bytes> decryptFacet(const SymmetricKey& facetKeyValue, const Node& node, uint32_t tag) {
  Result<FacetMap> facets = parseContent(node.content);
  if (!facets.ok()) {
    return facets.status();
  }
  auto found = facets.value().find(tag);
  if (found == facets.value().end()) {
    return Status::NotFound;
  }
  Bytes associatedData = facetAad(node.id, node.collection, tag, node.epoch, node.baseSeq, node.deleted);
  Result<Bytes> padded = aeadDecrypt(facetKeyValue, found->second, associatedData);
  if (!padded.ok()) {
    return padded.status();
  }
  return unpad(padded.value());
}

void sealContent(Node& node, const SymmetricKey& nodeKey, const FacetMap& plaintexts) {
  FacetMap ciphertexts;
  for (const auto& [tag, plaintext] : plaintexts) {
    ciphertexts.emplace(tag, encryptFacet(facetKey(nodeKey, tag), node.id, node.collection, tag, node.epoch,
                                          node.baseSeq, node.deleted, plaintext));
  }
  node.content = assembleContent(ciphertexts);
}

Result<FacetMap> openContent(const Node& node, const SymmetricKey& nodeKey) {
  Result<FacetMap> facets = parseContent(node.content);
  if (!facets.ok()) {
    return facets.status();
  }
  FacetMap plaintexts;
  for (const auto& [tag, ciphertext] : facets.value()) {
    Result<Bytes> plaintext = decryptFacet(facetKey(nodeKey, tag), node, tag);
    if (!plaintext.ok()) {
      return plaintext.status();
    }
    plaintexts.emplace(tag, plaintext.take());
  }
  return plaintexts;
}

size_t blobChunkCount(uint64_t size) {
  if (size == 0) {
    return 1;
  }
  return static_cast<size_t>((size + kBlobChunkBytes - 1) / kBlobChunkBytes);
}

Bytes encryptBlobChunk(const SymmetricKey& fileKeyValue, std::string_view nodeId, std::string_view objectId,
                       uint32_t index, bool finalChunk, ByteView plaintext) {
  return aeadEncrypt(fileKeyValue, plaintext, blobChunkAad(nodeId, objectId, index, finalChunk));
}

Result<Bytes> decryptBlobChunk(const SymmetricKey& fileKeyValue, std::string_view nodeId,
                               std::string_view objectId, uint32_t index, bool finalChunk, ByteView boxed) {
  return aeadDecrypt(fileKeyValue, boxed, blobChunkAad(nodeId, objectId, index, finalChunk));
}

Bytes nodeWriteMessage(const Node& node) {
  Bytes wrappedKeyBytes;
  if (node.wrappedKey.has_value()) {
    wrappedKeyBytes = *node.wrappedKey;
  }
  return TlvWriter("nw-node-write-v3")
      .text(node.id)
      .optionalText(node.parentId)
      .text(node.collection)
      .text(node.kind)
      .u32(node.epoch)
      .u64(node.baseSeq)
      .flag(node.deleted)
      .optionalText(node.targetId)
      .optionalText(node.targetRole)
      .bytes(hash(wrappedKeyBytes))
      .bytes(hash(node.content))
      .bytes(hash(canonicalFilesBytes(node.files)))
      .finish();
}

Status signNodeWrite(ByteView signSecret, Node& node) {
  Result<Bytes> signature = sign(signSecret, nodeWriteMessage(node));
  if (!signature.ok()) {
    return signature.status();
  }
  node.signature = signature.take();
  return Status::Ok;
}

bool verifyNodeWrite(ByteView signPub, const Node& node) {
  return verifySignature(signPub, nodeWriteMessage(node), node.signature);
}

}  // namespace nw
