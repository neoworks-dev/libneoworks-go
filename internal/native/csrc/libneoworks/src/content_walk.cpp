#include "content_walk.hpp"

#include <algorithm>

namespace nw {

namespace {

constexpr size_t kMaxNesting = 32;

void walkValue(const ValueShape& shape, const Json& value, uint32_t fieldOrdinal, size_t depth,
               const LeafVisitor& visit);

void walkModel(const ModelDescriptor& model, const Json& content, uint32_t topLevelOrdinal, size_t depth,
               const LeafVisitor& visit);

void walkOneof(const ValueShape& shape, const Json& value, uint32_t fieldOrdinal, size_t depth,
               const LeafVisitor& visit) {
  if (!value.is_object()) {
    return;
  }
  for (const OneofVariantDescriptor& variant : shape.variants) {
    auto chosen = value.find(variant.name);
    if (chosen != value.end()) {
      walkValue(variant.value, *chosen, fieldOrdinal, depth + 1, visit);
    }
  }
}

void walkValue(const ValueShape& shape, const Json& value, uint32_t fieldOrdinal, size_t depth,
               const LeafVisitor& visit) {
  if (depth > kMaxNesting) {
    return;
  }
  if (shape.kind == ValueKind::Message && shape.model != nullptr) {
    walkModel(*shape.model, value, fieldOrdinal, depth + 1, visit);
    return;
  }
  if (shape.kind == ValueKind::Oneof) {
    walkOneof(shape, value, fieldOrdinal, depth, visit);
    return;
  }
  visit(shape, value, fieldOrdinal);
}

void walkField(const FieldDescriptor& field, const Json& value, uint32_t topLevelOrdinal, size_t depth,
               const LeafVisitor& visit) {
  bool isMap = field.container.kind == ContainerKind::Map || field.container.kind == ContainerKind::WrapperMap;
  if (isMap && value.is_object()) {
    for (const auto& [key, entry] : value.items()) {
      walkValue(field.value, entry, topLevelOrdinal, depth, visit);
    }
    return;
  }
  if (value.is_array()) {
    for (const Json& element : value) {
      walkValue(field.value, element, topLevelOrdinal, depth, visit);
    }
    return;
  }
  walkValue(field.value, value, topLevelOrdinal, depth, visit);
}

void walkModel(const ModelDescriptor& model, const Json& content, uint32_t topLevelOrdinal, size_t depth,
               const LeafVisitor& visit) {
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
    walkField(field, *value, ordinal, depth, visit);
  }
}

}  // namespace

void walkContentLeaves(const ModelDescriptor& model, const Json& content, const LeafVisitor& visit) {
  walkModel(model, content, 0, 0, visit);
}

}  // namespace nw
