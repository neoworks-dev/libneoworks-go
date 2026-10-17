#include "files.hpp"

#include <algorithm>
#include <map>
#include <set>

#include "content_walk.hpp"
#include "schema_values.hpp"

namespace nw {

namespace {

std::optional<NodeFile> nodeFileOf(const Json& objectId, const Json& size) {
  if (!objectId.is_string() || !size.is_string()) {
    return std::nullopt;
  }
  std::optional<uint64_t> parsedSize = parseUnsignedDecimalText(size.get_ref<const std::string&>());
  const std::string& id = objectId.get_ref<const std::string&>();
  if (!parsedSize.has_value() || !isLowercaseUuid(id)) {
    return std::nullopt;
  }
  return NodeFile{id, static_cast<uint32_t>(blobChunkCount(*parsedSize)), *parsedSize};
}

bool appendEntry(const Json& entry, std::vector<NodeFile>& files) {
  if (!entry.is_object() || !entry.contains("objectId") || !entry.contains("size")) {
    return false;
  }
  std::optional<NodeFile> file = nodeFileOf(entry.at("objectId"), entry.at("size"));
  if (!file.has_value()) {
    return false;
  }
  files.push_back(*file);
  return true;
}

bool appendFileValue(const Json& value, std::vector<NodeFile>& files) {
  if (!appendEntry(value, files)) {
    return false;
  }
  auto variants = value.find("variants");
  if (variants == value.end() || !variants->is_object()) {
    return true;
  }
  for (const auto& [name, variant] : variants->items()) {
    if (!appendEntry(variant, files)) {
      return false;
    }
  }
  return true;
}

bool hasDistinctObjectIds(const std::vector<NodeFile>& files) {
  std::set<std::string> objectIds;
  return std::all_of(files.begin(), files.end(),
                     [&](const NodeFile& file) { return objectIds.insert(file.objectId).second; });
}

bool isSubsetOf(const std::vector<NodeFile>& seen, const std::vector<NodeFile>& listed) {
  return std::all_of(seen.begin(), seen.end(), [&](const NodeFile& file) {
    return std::find(listed.begin(), listed.end(), file) != listed.end();
  });
}

std::vector<const Json*> fileValuesOf(const ModelDescriptor& model, const Json& content) {
  std::vector<const Json*> values;
  walkContentLeaves(model, content, [&](const ValueShape& shape, const Json& value, uint32_t) {
    if (shape.kind == ValueKind::File && value.is_object()) {
      values.push_back(&value);
    }
  });
  return values;
}

bool holdsObject(const Json& file, std::string_view objectId) {
  auto original = file.find("objectId");
  if (original != file.end() && original->is_string() && original->get_ref<const std::string&>() == objectId) {
    return true;
  }
  auto variants = file.find("variants");
  if (variants == file.end() || !variants->is_object()) {
    return false;
  }
  return std::any_of(variants->begin(), variants->end(), [&](const Json& variant) {
    auto variantId = variant.find("objectId");
    return variantId != variant.end() && variantId->is_string() &&
           variantId->get_ref<const std::string&>() == objectId;
  });
}

Result<SymmetricKey> keyOfFile(const Json& file) {
  auto key = file.find("key");
  if (key == file.end() || !key->is_string()) {
    return Status::Malformed;
  }
  std::optional<Bytes> decoded = fromBase64Url(key->get_ref<const std::string&>());
  if (!decoded.has_value()) {
    return Status::Malformed;
  }
  return SymmetricKey::fromBytes(*decoded);
}

// The key text of every stored File by the object id of its original.
std::map<std::string, std::string> keyTextsByObjectId(const ModelDescriptor& model, const Json& stored) {
  std::map<std::string, std::string> keyTexts;
  for (const Json* file : fileValuesOf(model, stored)) {
    auto objectId = file->find("objectId");
    auto key = file->find("key");
    if (objectId != file->end() && objectId->is_string() && key != file->end() && key->is_string()) {
      keyTexts.emplace(objectId->get_ref<const std::string&>(), key->get_ref<const std::string&>());
    }
  }
  return keyTexts;
}

Status assignFileKey(Json& file, const std::map<std::string, std::string>& storedKeyTexts, CodecError& error) {
  if (file.contains("key")) {
    error.status = Status::InvalidArgument;
    error.path = fileModel().name + ".key";
    error.reason = "is set by the core";
    return Status::InvalidArgument;
  }
  auto objectId = file.find("objectId");
  if (objectId != file.end() && objectId->is_string()) {
    auto stored = storedKeyTexts.find(objectId->get_ref<const std::string&>());
    if (stored != storedKeyTexts.end()) {
      file["key"] = stored->second;
      return Status::Ok;
    }
  }
  file["key"] = toBase64Url(SymmetricKey::random().view());
  return Status::Ok;
}

}  // namespace

Result<SymmetricKey> findFileKey(const ModelDescriptor& model, const Json& content, std::string_view objectId) {
  for (const Json* file : fileValuesOf(model, content)) {
    if (holdsObject(*file, objectId)) {
      return keyOfFile(*file);
    }
  }
  return Status::NotFound;
}

bool holdsFile(const ModelDescriptor& model, const Json& content) { return !fileValuesOf(model, content).empty(); }

Status assignFileKeys(const ModelDescriptor& writtenModel, const ModelDescriptor& storedModel, Json& written,
                      const Json& stored, CodecError& error) {
  std::map<std::string, std::string> storedKeyTexts = keyTextsByObjectId(storedModel, stored);
  Status status = Status::Ok;
  walkContentLeaves(writtenModel, written, [&](const ValueShape& shape, Json& value, uint32_t) {
    if (shape.kind == ValueKind::File && value.is_object() && status == Status::Ok) {
      status = assignFileKey(value, storedKeyTexts, error);
    }
  });
  return status;
}

void removeFileKeys(const ModelDescriptor& model, Json& content) {
  walkContentLeaves(model, content, [](const ValueShape& shape, Json& value, uint32_t) {
    if (shape.kind == ValueKind::File && value.is_object()) {
      value.erase("key");
    }
  });
}

Result<std::vector<NodeFile>> collectFiles(const ModelDescriptor& model, const Json& content) {
  std::vector<NodeFile> files;
  bool wellFormed = true;
  walkContentLeaves(model, content, [&](const ValueShape& shape, const Json& value, uint32_t) {
    if (shape.kind == ValueKind::File) {
      wellFormed = appendFileValue(value, files) && wellFormed;
    }
  });
  if (!wellFormed) {
    return Status::Malformed;
  }
  if (!hasDistinctObjectIds(files)) {
    return Status::InvalidArgument;
  }
  return files;
}

Result<std::vector<NodeFile>> filesOfFacets(const TableDescriptor& descriptor, const FacetMap& plaintexts,
                                            CodecError& error) {
  Result<Json> content = decodeContent(descriptor, plaintexts, error);
  if (!content.ok()) {
    return content.status();
  }
  Result<std::vector<NodeFile>> files = collectFiles(*descriptor.model, content.value());
  if (files.status() == Status::InvalidArgument) {
    error.status = Status::InvalidArgument;
    error.path = descriptor.model->name;
    error.reason = "an object id is used by more than one file";
  }
  return files;
}

Status checkNodeFiles(const TableDescriptor& descriptor, const Node& node, const Json& content) {
  Result<std::vector<NodeFile>> seen = collectFiles(*descriptor.model, content);
  if (!seen.ok() || !isSubsetOf(seen.value(), node.files)) {
    return Status::IntegrityFailure;
  }
  return Status::Ok;
}

}  // namespace nw
