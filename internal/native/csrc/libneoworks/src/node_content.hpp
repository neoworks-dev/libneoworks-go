#pragma once

#include <functional>

#include "descriptor.hpp"
#include "node.hpp"
#include "schema_codec.hpp"

namespace nw {

// Splits `object`, a JSON object of the node model, into one plaintext per facet. A facet
// with nothing set is left out. `previous` holds the node's current plaintexts: their
// unknown fields are kept, and so are facets the descriptor does not know. With
// `keepMissing`, fields missing from `object` keep their current value and null clears.
Result<FacetMap> encodeContent(const NodeDescriptor& node, const Json& object, const FacetMap& previous,
                               bool keepMissing, CodecError& error);

// One JSON object holding the fields of every facet in `readable`. A facet this reader can
// open but the node does not carry must be present with empty plaintext, so its required
// fields are enforced.
Result<Json> decodeContent(const NodeDescriptor& node, const FacetMap& readable, CodecError& error);

// The facet key for a tag, or a failure when this reader cannot open the facet.
using FacetKeyResolver = std::function<Result<SymmetricKey>(uint32_t tag)>;

// Plaintext of every descriptor facet the resolver opens; empty for facets the node does
// not carry. AuthenticationFailed when a facet does not decrypt.
Result<FacetMap> readableFacets(const Node& node, const NodeDescriptor& descriptor, const FacetKeyResolver& keyFor);

// The ordinals of a facet's fields.
std::set<uint32_t> facetFieldSet(const FacetDescriptor& facet);

}  // namespace nw
