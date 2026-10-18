#pragma once

#include <string_view>
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
Result<std::vector<NodeFile>> filesOfFacets(const TableDescriptor& descriptor, const FacetMap& plaintexts,
                                            CodecError& error);

// The key of the file that has an object with `objectId`, its original or one of its variants,
// among the File values of `content`. NotFound when `content` holds no such object, as when it is
// in a facet the reader cannot open.
Result<SymmetricKey> findFileKey(const ModelDescriptor& model, const Json& content, std::string_view objectId);

// Whether `content` holds a File value, wherever it sits.
bool holdsFile(const ModelDescriptor& model, const Json& content);

// A row's content as stored, with the keys of its Files, in the shape of `model`.
struct StoredFileContent {
  const ModelDescriptor* model = nullptr;
  const Json* content = nullptr;
};

// Gives every File value in `written`, the content an app writes, the key of the File with the
// same object id in `stored`, the contents the record holds now and held before, or a new random
// key when there is none. `stored` lists the current content first, so it decides when an object
// id appears with more than one key. `written` is in the shape of `writtenModel`; each stored
// content is in that of its own model, and these differ when a row moves to another schema
// version. InvalidArgument when the app gives a key itself.
Status assignFileKeys(const ModelDescriptor& writtenModel, Json& written, const std::vector<StoredFileContent>& stored,
                      CodecError& error);

// Takes the keys out of the File values of `content`, which is what an app may see.
void removeFileKeys(const ModelDescriptor& model, Json& content);

// IntegrityFailure unless every file in `content`, the decoded readable facets of `node`, is in
// the plain list of `node`. The list may hold more: a reader whose descriptor predates a File
// field does not see that field's files, and opening them needs the record's key anyway.
Status checkNodeFiles(const TableDescriptor& descriptor, const Node& node, const Json& content);

}  // namespace nw
