#pragma once

#include <string>
#include <vector>

#include "descriptor.hpp"
#include "json.hpp"

namespace nw {

// One node id a node's content refers to, and the top-level field of the node model it was
// found in (the field decides the facet the reference is encrypted in).
struct ContentReference {
  uint32_t fieldOrdinal = 0;
  std::string nodeId;
};

// The values of fields declared with a reference (`ref<Model>`) in `content`, a JSON object of
// `model` as the core reads it, wherever they sit: in lists, maps, nested messages and oneofs.
// In field order; an id that appears more than once is listed once per field.
std::vector<ContentReference> collectReferences(const ModelDescriptor& model, const Json& content);

}  // namespace nw
