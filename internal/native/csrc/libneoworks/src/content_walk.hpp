#pragma once

#include <cstdint>
#include <functional>

#include "descriptor.hpp"
#include "json.hpp"

namespace nw {

// Called with a value that holds no further values of its own: a scalar, enum, decimal or File,
// and the top-level field of the node model it sits in (the field decides its facet).
using LeafVisitor = std::function<void(const ValueShape& shape, const Json& value, uint32_t topLevelOrdinal)>;
using MutableLeafVisitor = std::function<void(const ValueShape& shape, Json& value, uint32_t topLevelOrdinal)>;

// Visits the leaf values of `content`, a JSON object of `model` as the core reads it, wherever
// they sit: in lists, maps, nested messages and oneofs. In field order.
void walkContentLeaves(const ModelDescriptor& model, const Json& content, const LeafVisitor& visit);

// The same walk, handing out values the visitor may change in place.
void walkContentLeaves(const ModelDescriptor& model, Json& content, const MutableLeafVisitor& visit);

}  // namespace nw
