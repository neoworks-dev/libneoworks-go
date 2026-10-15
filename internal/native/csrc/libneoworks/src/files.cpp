#include "files.hpp"

#include <algorithm>
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

std::vector<NodeFile> sortedByObjectId(std::vector<NodeFile> files) {
  std::sort(files.begin(), files.end(),
            [](const NodeFile& left, const NodeFile& right) { return left.objectId < right.objectId; });
  return files;
}

bool facetHoldsFile(const NodeDescriptor& descriptor, const FacetDescriptor& facet) {
  return std::any_of(facet.fields.begin(), facet.fields.end(), [&](uint32_t ordinal) {
    return shapeHoldsFile(descriptor.model->fieldByOrdinal(ordinal)->value);
  });
}

// Whether every facet that holds a File is among the readable ones.
bool readsEveryFileFacet(const NodeDescriptor& descriptor, const FacetMap& readable) {
  return std::all_of(descriptor.facets.begin(), descriptor.facets.end(), [&](const FacetDescriptor& facet) {
    return readable.count(facet.tag) != 0 || !facetHoldsFile(descriptor, facet);
  });
}

bool isSubsetOf(const std::vector<NodeFile>& seen, const std::vector<NodeFile>& listed) {
  return std::all_of(seen.begin(), seen.end(), [&](const NodeFile& file) {
    return std::find(listed.begin(), listed.end(), file) != listed.end();
  });
}

}  // namespace

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

Result<std::vector<NodeFile>> filesOfFacets(const NodeDescriptor& descriptor, const FacetMap& plaintexts,
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

Status checkNodeFiles(const NodeDescriptor& descriptor, const Node& node, const FacetMap& readable,
                      const Json& content) {
  Result<std::vector<NodeFile>> seen = collectFiles(*descriptor.model, content);
  if (!seen.ok()) {
    return Status::IntegrityFailure;
  }
  std::vector<NodeFile> seenSorted = sortedByObjectId(seen.take());
  std::vector<NodeFile> listedSorted = sortedByObjectId(node.files);
  bool agrees = isSubsetOf(seenSorted, listedSorted);
  if (readsEveryFileFacet(descriptor, readable)) {
    agrees = seenSorted == listedSorted;
  }
  if (!agrees) {
    return Status::IntegrityFailure;
  }
  return Status::Ok;
}

}  // namespace nw
