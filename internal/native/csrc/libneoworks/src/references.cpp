#include "references.hpp"

#include "content_walk.hpp"

namespace nw {

std::vector<ContentReference> collectReferences(const ModelDescriptor& model, const Json& content) {
  std::vector<ContentReference> found;
  walkContentLeaves(model, content, [&](const ValueShape& shape, const Json& value, uint32_t fieldOrdinal) {
    bool isReference = shape.kind == ValueKind::Scalar && !shape.reference.empty() && value.is_string();
    if (isReference) {
      found.push_back(ContentReference{fieldOrdinal, value.get<std::string>()});
    }
  });
  return found;
}

}  // namespace nw
