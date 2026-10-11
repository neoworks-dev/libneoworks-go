#include "references.hpp"

#include <algorithm>

namespace nw {

namespace {

constexpr size_t kMaxNesting = 32;

void collectFromValue(const ValueShape& shape, const Json& value, uint32_t fieldOrdinal, size_t depth,
                      std::vector<ContentReference>& found);

void collectFromModel(const ModelDescriptor& model, const Json& content, uint32_t topLevelOrdinal, size_t depth,
                      std::vector<ContentReference>& found);

void collectFromOneof(const ValueShape& shape, const Json& value, uint32_t fieldOrdinal, size_t depth,
                      std::vector<ContentReference>& found) {
  if (!value.is_object()) {
    return;
  }
  for (const OneofVariantDescriptor& variant : shape.variants) {
    auto chosen = value.find(variant.name);
    if (chosen != value.end()) {
      collectFromValue(variant.value, *chosen, fieldOrdinal, depth + 1, found);
    }
  }
}

void collectFromValue(const ValueShape& shape, const Json& value, uint32_t fieldOrdinal, size_t depth,
                      std::vector<ContentReference>& found) {
  if (depth > kMaxNesting) {
    return;
  }
  if (shape.kind == ValueKind::Scalar && !shape.reference.empty() && value.is_string()) {
    found.push_back(ContentReference{fieldOrdinal, value.get<std::string>()});
    return;
  }
  if (shape.kind == ValueKind::Message && shape.model != nullptr) {
    collectFromModel(*shape.model, value, fieldOrdinal, depth + 1, found);
    return;
  }
  if (shape.kind == ValueKind::Oneof) {
    collectFromOneof(shape, value, fieldOrdinal, depth, found);
  }
}

void collectFromField(const FieldDescriptor& field, const Json& value, uint32_t topLevelOrdinal, size_t depth,
                      std::vector<ContentReference>& found) {
  bool isMap = field.container.kind == ContainerKind::Map || field.container.kind == ContainerKind::WrapperMap;
  if (isMap && value.is_object()) {
    for (const auto& [key, entry] : value.items()) {
      collectFromValue(field.value, entry, topLevelOrdinal, depth, found);
    }
    return;
  }
  if (value.is_array()) {
    for (const Json& element : value) {
      collectFromValue(field.value, element, topLevelOrdinal, depth, found);
    }
    return;
  }
  collectFromValue(field.value, value, topLevelOrdinal, depth, found);
}

void collectFromModel(const ModelDescriptor& model, const Json& content, uint32_t topLevelOrdinal, size_t depth,
                      std::vector<ContentReference>& found) {
  if (!content.is_object() || depth > kMaxNesting) {
    return;
  }
  for (const FieldDescriptor& field : model.fields) {
    auto value = content.find(field.name);
    if (value == content.end() || value->is_null()) {
      continue;
    }
    uint32_t ordinal = topLevelOrdinal;
    if (depth == 0) {
      ordinal = field.ordinal;
    }
    collectFromField(field, *value, ordinal, depth, found);
  }
}

}  // namespace

std::vector<ContentReference> collectReferences(const ModelDescriptor& model, const Json& content) {
  std::vector<ContentReference> found;
  collectFromModel(model, content, 0, 0, found);
  return found;
}

}  // namespace nw
