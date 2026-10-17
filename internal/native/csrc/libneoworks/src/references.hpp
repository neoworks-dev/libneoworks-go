#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "descriptor.hpp"
#include "json.hpp"
#include "schema_codec.hpp"

namespace nw {

// One reference in a row's content, and the top-level field of the table it was found in.
struct ContentReference {
  uint32_t fieldOrdinal = 0;
  std::string rowId;
};

// Every reference in `content`, a JSON object of `model` as the core stores it (a reference as
// {id, key?}) or as an app sees it (a reference as its id), wherever it sits: in lists, maps,
// nested messages and oneofs. In field order.
std::vector<ContentReference> collectReferences(const ModelDescriptor& model, const Json& content);

// The rows `content` links to: every reference but the @belongsTo field, ascending and distinct.
std::vector<std::string> linksOf(const TableDescriptor& table, const Json& content);

// The row a row with this content belongs to; nullopt when the table has no @belongsTo or the
// field is not set.
std::optional<std::string> belongsToOf(const TableDescriptor& table, const Json& content);

// The key `content`, stored content of `model`, carries for the row `rowId`. NotFound when no
// reference to that row carries one.
Result<SymmetricKey> findReferenceKey(const ModelDescriptor& model, const Json& content, std::string_view rowId);

// The key of the row `rowId`, a row of the table with the qualified name `table`.
using RowKeyResolver = std::function<Result<SymmetricKey>(const std::string& rowId, const std::string& table)>;

// Turns every reference in `written`, the content an app writes with a reference as its id, into
// {id, key} with the key from `keyFor`; the @belongsTo field becomes {id} alone. InvalidArgument
// when a reference is not an id; otherwise the failure of `keyFor`.
Status assignReferenceKeys(const TableDescriptor& table, Json& written, const RowKeyResolver& keyFor,
                           CodecError& error);

// Turns every reference in `content` into its id, which is all an app sees of it.
void removeReferenceKeys(const ModelDescriptor& model, Json& content);

}  // namespace nw
