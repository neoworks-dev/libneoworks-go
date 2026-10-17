#include "node.hpp"

#include <algorithm>
#include <set>

#include "semver.hpp"
#include "tlv.hpp"
#include "wire.hpp"

namespace nw {

namespace {

constexpr std::string_view kFacetContext = "nwfacet1";
constexpr std::string_view kObjectKeyContext = "nwfile02";
constexpr std::string_view kKinds[] = {"root", "row"};
constexpr std::string_view kPrincipalTypes[] = {"user", "install"};
constexpr size_t kMaxRegistrySegment = 64;
constexpr size_t kMaxTableName = 128;

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

bool isValidTable(std::string_view table) {
  if (table.empty() || table.size() > kMaxTableName) {
    return false;
  }
  auto identifierCharacter = [](char character) {
    bool letter = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
    return letter || (character >= '0' && character <= '9') || character == '_';
  };
  bool leadsWell = !(table.front() >= '0' && table.front() <= '9');
  return leadsWell && std::all_of(table.begin(), table.end(), identifierCharacter);
}
bool isValidPrincipalType(std::string_view principalType) { return isOneOf(kPrincipalTypes, principalType); }
bool isRoot(const Node& node) { return node.kind == "root"; }

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

Result<std::vector<std::string>> linksFromJson(const Json& json) {
  if (!json.is_array()) {
    return Status::Malformed;
  }
  std::vector<std::string> links;
  for (const Json& entry : json) {
    bool ascending = links.empty() || (entry.is_string() && entry.get_ref<const std::string&>() > links.back());
    if (!entry.is_string() || !isLowercaseUuid(entry.get_ref<const std::string&>()) || !ascending) {
      return Status::Malformed;
    }
    links.push_back(entry.get<std::string>());
  }
  return links;
}

Bytes canonicalLinksBytes(const std::vector<std::string>& links) {
  if (links.empty()) {
    return Bytes();
  }
  return bytesOf(dumpCompact(Json(links)));
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
  json["table"] = Json(nullptr);
  if (node.table.has_value()) {
    json["table"] = *node.table;
  }
  json["wrappedKey"] = Json(nullptr);
  if (node.wrappedKey.has_value()) {
    json["wrappedKey"] = bytesToJson(*node.wrappedKey);
  }
  json["content"] = toBase64Url(node.content);
  json["files"] = filesToJson(node.files);
  json["links"] = Json(node.links);
  if (node.schemaVersion.has_value()) {
    json["schemaVersion"] = *node.schemaVersion;
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
  return json;
}

namespace {

struct NodeScalars {
  std::optional<std::string> id, ownerId, collection, kind, authorType, authorId, createdAt, updatedAt;
  std::optional<uint64_t> baseSeq, seq;
  std::optional<bool> deleted;
  std::optional<Bytes> signature;
  std::optional<Bytes> content;

  bool complete() const {
    return id && ownerId && collection && kind && authorType && authorId && createdAt && updatedAt && baseSeq &&
           seq && deleted && signature && content;
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
  scalars.baseSeq = readUnsigned(json, "baseSeq");
  scalars.seq = readUnsigned(json, "seq");
  scalars.deleted = readBool(json, "deleted");
  scalars.signature = readBytes(json, "signature");
  scalars.content = readBytes(json, "content");
  return scalars;
}

// Lists a writer leaves out read as empty.
Json arrayOrEmpty(const Json& json, const char* key) {
  if (!json.contains(key)) {
    return Json::array();
  }
  return json.at(key);
}

}  // namespace

Result<Node> nodeFromJson(const Json& json) {
  NodeScalars scalars = readNodeScalars(json);
  if (!scalars.complete()) {
    return Status::Malformed;
  }
  bool wellFormed = true;
  Node node;
  node.parentId = readOptionalString(json, "parentId", wellFormed);
  node.wrappedKey = readOptionalBytes(json, "wrappedKey", wellFormed);
  node.certId = readOptionalString(json, "certId", wellFormed);
  node.table = readOptionalString(json, "table", wellFormed);
  node.schemaVersion = readOptionalString(json, "schemaVersion", wellFormed);
  if (!wellFormed) {
    return Status::Malformed;
  }
  node.content = std::move(*scalars.content);
  Result<std::vector<NodeFile>> files = filesFromJson(arrayOrEmpty(json, "files"));
  if (!files.ok()) {
    return files.status();
  }
  node.files = files.take();
  Result<std::vector<std::string>> links = linksFromJson(arrayOrEmpty(json, "links"));
  if (!links.ok()) {
    return links.status();
  }
  node.links = links.take();
  node.id = *scalars.id;
  node.ownerId = *scalars.ownerId;
  node.collection = *scalars.collection;
  node.kind = *scalars.kind;
  node.deleted = *scalars.deleted;
  node.baseSeq = *scalars.baseSeq;
  node.seq = *scalars.seq;
  node.authorType = *scalars.authorType;
  node.authorId = *scalars.authorId;
  node.signature = std::move(*scalars.signature);
  node.createdAt = *scalars.createdAt;
  node.updatedAt = *scalars.updatedAt;
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
  return !node.certId.has_value() || isLowercaseUuid(*node.certId);
}

bool hasValidParentage(const Node& node) {
  if (isRoot(node)) {
    bool empty = node.content.empty() && node.files.empty() && node.links.empty() && !node.table.has_value();
    return !node.parentId.has_value() && !node.wrappedKey.has_value() && empty;
  }
  bool named = node.table.has_value() && isValidTable(*node.table);
  return named && node.parentId.has_value() && node.wrappedKey.has_value() && *node.parentId != node.id;
}

// Links are distinct uuids in ascending order, and a row never links to itself.
bool hasValidLinks(const Node& node) {
  for (size_t index = 0; index < node.links.size(); ++index) {
    const std::string& link = node.links[index];
    bool ascending = index == 0 || link > node.links[index - 1];
    if (!isLowercaseUuid(link) || !ascending || link == node.id) {
      return false;
    }
  }
  return true;
}

bool hasValidSchemaVersion(const Node& node) {
  if (!node.schemaVersion.has_value()) {
    return true;
  }
  return node.kind != "root" && parseSemverText(*node.schemaVersion).has_value();
}

bool hasValidAuthor(const Node& node) {
  if (node.authorType == "user") {
    return !node.certId.has_value();
  }
  return node.authorType == "install" && node.certId.has_value();
}

}  // namespace

Status validateNodeShape(const Node& node) {
  bool structurallyValid = isValidCollection(node.collection) && isValidKind(node.kind) &&
                           hasValidIdentifiers(node) && hasValidParentage(node) && hasValidLinks(node) &&
                           parseContent(node.content).ok() && hasValidAuthor(node) && hasValidSchemaVersion(node);
  if (!structurallyValid) {
    return Status::Malformed;
  }
  return Status::Ok;
}

Bytes nodeKeyWrapAad(std::string_view id, const std::optional<std::string>& parentId) {
  return TlvWriter("nw-node-key-v2").text(id).optionalText(parentId).finish();
}

Bytes facetAad(std::string_view id, std::string_view collection, uint32_t tag, uint64_t baseSeq, bool deleted) {
  return TlvWriter("nw-node-content-v3")
      .text(id)
      .text(collection)
      .u32(tag)
      .u64(baseSeq)
      .flag(deleted)
      .finish();
}

Bytes blobChunkAad(std::string_view objectId, uint32_t index, bool finalChunk) {
  return TlvWriter("nw-blob-chunk-v2").text(objectId).u32(index).flag(finalChunk).finish();
}

SymmetricKey facetKey(const SymmetricKey& nodeKey, uint32_t tag) { return kdf(nodeKey, tag, kFacetContext); }

SymmetricKey objectKey(const SymmetricKey& fileKey, std::string_view objectId) {
  Bytes input = bytesOf(kObjectKeyContext);
  Bytes id = bytesOf(objectId);
  input.insert(input.end(), id.begin(), id.end());
  return keyedHash(fileKey, input);
}

Bytes wrapNodeKey(const SymmetricKey& parentKey, const SymmetricKey& nodeKey, std::string_view id,
                  const std::optional<std::string>& parentId) {
  return aeadEncrypt(parentKey, nodeKey.view(), nodeKeyWrapAad(id, parentId));
}

Result<SymmetricKey> unwrapNodeKey(const SymmetricKey& parentKey, ByteView wrappedKey, std::string_view id,
                                   const std::optional<std::string>& parentId) {
  return aeadDecryptKey(parentKey, wrappedKey, nodeKeyWrapAad(id, parentId));
}

Bytes encryptFacet(const SymmetricKey& facetKeyValue, std::string_view id, std::string_view collection,
                   uint32_t tag, uint64_t baseSeq, bool deleted, ByteView plaintext) {
  Bytes associatedData = facetAad(id, collection, tag, baseSeq, deleted);
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
  Bytes associatedData = facetAad(node.id, node.collection, tag, node.baseSeq, node.deleted);
  Result<Bytes> padded = aeadDecrypt(facetKeyValue, found->second, associatedData);
  if (!padded.ok()) {
    return padded.status();
  }
  return unpad(padded.value());
}

void sealContent(Node& node, const SymmetricKey& nodeKey, const FacetMap& plaintexts) {
  FacetMap ciphertexts;
  for (const auto& [tag, plaintext] : plaintexts) {
    ciphertexts.emplace(tag, encryptFacet(facetKey(nodeKey, tag), node.id, node.collection, tag, node.baseSeq,
                                          node.deleted, plaintext));
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

Bytes encryptBlobChunk(const SymmetricKey& objectKeyValue, std::string_view objectId, uint32_t index,
                       bool finalChunk, ByteView plaintext) {
  return aeadEncrypt(objectKeyValue, plaintext, blobChunkAad(objectId, index, finalChunk));
}

Result<Bytes> decryptBlobChunk(const SymmetricKey& objectKeyValue, std::string_view objectId, uint32_t index,
                               bool finalChunk, ByteView boxed) {
  return aeadDecrypt(objectKeyValue, boxed, blobChunkAad(objectId, index, finalChunk));
}

Bytes nodeWriteMessage(const Node& node) {
  Bytes wrappedKeyBytes;
  if (node.wrappedKey.has_value()) {
    wrappedKeyBytes = *node.wrappedKey;
  }
  return TlvWriter("nw-node-write-v4")
      .text(node.id)
      .optionalText(node.parentId)
      .text(node.collection)
      .text(node.kind)
      .optionalText(node.table)
      .u64(node.baseSeq)
      .flag(node.deleted)
      .bytes(hash(wrappedKeyBytes))
      .bytes(hash(node.content))
      .bytes(hash(canonicalFilesBytes(node.files)))
      .bytes(hash(canonicalLinksBytes(node.links)))
      .optionalText(node.schemaVersion)
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
