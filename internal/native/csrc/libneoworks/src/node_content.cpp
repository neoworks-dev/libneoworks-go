#include "node_content.hpp"

namespace nw {

namespace {

bool rejectUnknownNames(const ModelDescriptor& model, const Json& object, CodecError& error) {
  for (const auto& item : object.items()) {
    if (model.fieldByName(item.key()) != nullptr) {
      continue;
    }
    error.status = Status::InvalidArgument;
    error.path = model.name + "." + item.key();
    error.reason = "is not a field of " + model.name;
    return false;
  }
  return true;
}

ByteView previousFacet(const FacetMap& previous, uint32_t tag) {
  auto found = previous.find(tag);
  if (found == previous.end()) {
    return ByteView();
  }
  return found->second;
}

void keepUnknownFacets(const TableDescriptor& table, const FacetMap& previous, FacetMap& plaintexts) {
  for (const auto& [tag, plaintext] : previous) {
    if (table.facetByTag(tag) == nullptr) {
      plaintexts.emplace(tag, plaintext);
    }
  }
}

}  // namespace

std::set<uint32_t> facetFieldSet(const FacetDescriptor& facet) {
  return std::set<uint32_t>(facet.fields.begin(), facet.fields.end());
}

Result<FacetMap> encodeContent(const TableDescriptor& table, const Json& object, const FacetMap& previous,
                               bool keepMissing, CodecError& error) {
  error = CodecError{};
  if (!object.is_object()) {
    error.status = Status::InvalidArgument;
    error.path = table.model->name;
    error.reason = "expected an object";
    return Status::InvalidArgument;
  }
  if (!rejectUnknownNames(*table.model, object, error)) {
    return Status::InvalidArgument;
  }
  FacetMap plaintexts;
  for (const FacetDescriptor& facet : table.facets) {
    std::set<uint32_t> fields = facetFieldSet(facet);
    EncodeOptions options;
    options.fields = &fields;
    options.previous = previousFacet(previous, facet.tag);
    options.keepMissing = keepMissing;
    Result<Bytes> encoded = encodeMessage(*table.model, object, options, error);
    if (!encoded.ok()) {
      return encoded.status();
    }
    if (!encoded.value().empty()) {
      plaintexts.emplace(facet.tag, encoded.take());
    }
  }
  keepUnknownFacets(table, previous, plaintexts);
  return plaintexts;
}

Result<FacetMap> readableFacets(const Node& node, const TableDescriptor& table, const FacetKeyResolver& keyFor) {
  Result<FacetMap> stored = parseContent(node.content);
  if (!stored.ok()) {
    return stored.status();
  }
  FacetMap readable;
  for (const FacetDescriptor& facet : table.facets) {
    Result<SymmetricKey> key = keyFor(facet.tag);
    if (!key.ok()) {
      continue;
    }
    if (stored.value().count(facet.tag) == 0) {
      readable.emplace(facet.tag, Bytes());
      continue;
    }
    Result<Bytes> plaintext = decryptFacet(key.value(), node, facet.tag);
    if (!plaintext.ok()) {
      return plaintext.status();
    }
    readable.emplace(facet.tag, plaintext.take());
  }
  return readable;
}

Result<Json> decodeContent(const TableDescriptor& table, const FacetMap& readable, CodecError& error) {
  error = CodecError{};
  Json merged = Json::object();
  for (const FacetDescriptor& facet : table.facets) {
    auto found = readable.find(facet.tag);
    if (found == readable.end()) {
      continue;
    }
    std::set<uint32_t> fields = facetFieldSet(facet);
    Result<Json> decoded = decodeMessage(*table.model, found->second, &fields, error);
    if (!decoded.ok()) {
      return decoded.status();
    }
    merged.update(decoded.value());
  }
  return merged;
}

}  // namespace nw
