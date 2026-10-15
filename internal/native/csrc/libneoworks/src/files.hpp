#pragma once

#include <vector>

#include "node.hpp"
#include "node_content.hpp"

namespace nw {

// The plain file list for a node's content, `content` being a JSON object of the node model as the
// core reads it: for every `File` its original and then its variants, in field order, with the
// chunk count taken from the size. Malformed when the content holds a File the codec would not
// have produced; InvalidArgument when an object id appears twice.
Result<std::vector<NodeFile>> collectFiles(const ModelDescriptor& model, const Json& content);

// The file list of a node whose facets hold `plaintexts`.
Result<std::vector<NodeFile>> filesOfFacets(const NodeDescriptor& descriptor, const FacetMap& plaintexts,
                                            CodecError& error);

// IntegrityFailure unless every file in `content`, the decoded readable facets of `node`, is in
// the plain list of `node`. The list may hold more: a reader whose descriptor predates a File
// field does not see that field's files, and opening them needs the record's key anyway.
Status checkNodeFiles(const NodeDescriptor& descriptor, const Node& node, const Json& content);

}  // namespace nw
