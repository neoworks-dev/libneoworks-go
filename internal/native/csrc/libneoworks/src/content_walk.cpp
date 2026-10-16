#include "content_walk.hpp"

#include <algorithm>

namespace nw {

namespace {

constexpr size_t kMaxNesting = 32;

// `Content` is `const Json` or `Json`, and `Visitor` the matching visitor type.
template <typename Content, typename Visitor>
void walkValue(const ValueShape& shape, Content& value, uint32_t fieldOrdinal, size_t depth, const Visitor& visit);

template <typename Content, typename Visitor>
void walkModel(const ModelDescriptor& model, Content& content, uint32_t topLevelOrdinal, size_t depth,
               const Visitor& visit);

template <typename Content, typename Visitor>
void walkOneof(const ValueShape& shape, Content& value, uint32_t fieldOrdinal, size_t depth, const Visitor& visit) {
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

template <typename Content, typename Visitor>
void walkValue(const ValueShape& shape, Content& value, uint32_t fieldOrdinal, size_t depth, const Visitor& visit) {
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

template <typename Content, typename Visitor>
void walkField(const FieldDescriptor& field, Content& value, uint32_t topLevelOrdinal, size_t depth,
               const Visitor& visit) {
  bool isMap = field.container.kind == ContainerKind::Map || field.container.kind == ContainerKind::WrapperMap;
  bool isCollection = (isMap && value.is_object()) || value.is_array();
  if (!isCollection) {
    walkValue(field.value, value, topLevelOrdinal, depth, visit);
    return;
  }
  for (auto entry = value.begin(); entry != value.end(); ++entry) {
    walkValue(field.value, entry.value(), topLevelOrdinal, depth, visit);
  }
}

template <typename Content, typename Visitor>
void walkModel(const ModelDescriptor& model, Content& content, uint32_t topLevelOrdinal, size_t depth,
               const Visitor& visit) {
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

void walkContentLeaves(const ModelDescriptor& model, Json& content, const MutableLeafVisitor& visit) {
  walkModel(model, content, 0, 0, visit);
}

}  // namespace nw
