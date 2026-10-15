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

// IntegrityFailure unless the plain list of `node` agrees with the files in `content`, the
// decoded `readable` facets. A reader who opens every facet that holds a File needs the two to be
// the same set; a reader with fewer facets needs what it sees to be in the list.
Status checkNodeFiles(const NodeDescriptor& descriptor, const Node& node, const FacetMap& readable,
                      const Json& content);

}  // namespace nw
