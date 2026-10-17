#pragma once

#include <functional>
#include <string>

#include "descriptor.hpp"
#include "node.hpp"
#include "schema_codec.hpp"

namespace nw {

// Splits `object`, a JSON object of the table's model, into one plaintext per facet. A facet with
// nothing set is left out. `previous` holds the row's current plaintexts: their unknown fields are
// kept, and so are facets the descriptor does not know. With `keepMissing`, fields missing from
// `object` keep their current value and null clears.
Result<FacetMap> encodeContent(const TableDescriptor& table, const Json& object,
                               const FacetMap& previous, bool keepMissing, CodecError& error);

// One JSON object holding the fields of every facet of the table in `readable`. A facet this
// reader can open but the row does not carry must be present with empty plaintext, so its
// required fields are enforced.
Result<Json> decodeContent(const TableDescriptor& table, const FacetMap& readable, CodecError& error);

// The facet key for a tag, or a failure when this reader cannot open the facet.
using FacetKeyResolver = std::function<Result<SymmetricKey>(uint32_t tag)>;

// Plaintext of every facet of the table the resolver opens; empty for facets the row does not
// carry. AuthenticationFailed when a facet does not decrypt.
Result<FacetMap> readableFacets(const Node& node, const TableDescriptor& table, const FacetKeyResolver& keyFor);

// The ordinals of a facet's fields.
std::set<uint32_t> facetFieldSet(const FacetDescriptor& facet);

}  // namespace nw
