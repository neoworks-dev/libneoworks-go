#include "references.hpp"

#include <set>

#include "content_walk.hpp"

namespace nw {

namespace {

// The id of a reference as stored ({id, key?}) or as an app gives it (the id).
std::optional<std::string> referencedId(const Json& value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  if (!value.is_object()) {
    return std::nullopt;
  }
  auto id = value.find("id");
  if (id == value.end() || !id->is_string()) {
    return std::nullopt;
  }
  return id->get<std::string>();
}

Result<SymmetricKey> keyOfReference(const Json& value) {
  auto key = value.find("key");
  if (key == value.end() || !key->is_string()) {
    return Status::NotFound;
  }
  std::optional<Bytes> decoded = fromBase64Url(key->get_ref<const std::string&>());
  if (!decoded.has_value()) {
    return Status::Malformed;
  }
  return SymmetricKey::fromBytes(*decoded);
}

bool isBelongsTo(const TableDescriptor& table, uint32_t ordinal) {
  return table.belongsTo.has_value() && *table.belongsTo == ordinal;
}

Status failReference(CodecError& error, const std::string& path, Status status, const std::string& reason) {
  error.status = status;
  error.path = path;
  error.reason = reason;
  return status;
}

Status assignReferenceKey(const TableDescriptor& table, const ValueShape& shape, Json& value, uint32_t ordinal,
                          const RowKeyResolver& keyFor, CodecError& error) {
  std::string path = table.modelName + "." + table.model->fieldByOrdinal(ordinal)->name;
  if (!value.is_string() || !isLowercaseUuid(value.get_ref<const std::string&>())) {
    return failReference(error, path, Status::InvalidArgument, "a reference is the id of a row");
  }
  std::string rowId = value.get<std::string>();
  Result<SymmetricKey> key = keyFor(rowId, shape.reference);
  if (!key.ok()) {
    return failReference(error, path, key.status(), "no readable " + shape.reference + " " + rowId);
  }
  value = Json::object();
  value["id"] = rowId;
  if (!isBelongsTo(table, ordinal)) {
    value["key"] = toBase64Url(key.value().view());
  }
  return Status::Ok;
}

}  // namespace

std::vector<ContentReference> collectReferences(const ModelDescriptor& model, const Json& content) {
  std::vector<ContentReference> found;
  walkContentLeaves(model, content, [&](const ValueShape& shape, const Json& value, uint32_t fieldOrdinal) {
    std::optional<std::string> rowId = referencedId(value);
    if (shape.kind == ValueKind::Reference && rowId.has_value()) {
      found.push_back(ContentReference{fieldOrdinal, *rowId});
    }
  });
  return found;
}

std::vector<std::string> linksOf(const TableDescriptor& table, const Json& content) {
  std::set<std::string> links;
  for (const ContentReference& reference : collectReferences(*table.model, content)) {
    if (!isBelongsTo(table, reference.fieldOrdinal)) {
      links.insert(reference.rowId);
    }
  }
  return std::vector<std::string>(links.begin(), links.end());
}

std::optional<std::string> belongsToOf(const TableDescriptor& table, const Json& content) {
  if (!table.belongsTo.has_value() || !content.is_object()) {
    return std::nullopt;
  }
  auto value = content.find(table.model->fieldByOrdinal(*table.belongsTo)->name);
  if (value == content.end() || value->is_null()) {
    return std::nullopt;
  }
  return referencedId(*value);
}

Result<SymmetricKey> findReferenceKey(const ModelDescriptor& model, const Json& content, std::string_view rowId) {
  Result<SymmetricKey> found = Status::NotFound;
  walkContentLeaves(model, content, [&](const ValueShape& shape, const Json& value, uint32_t) {
    std::optional<std::string> id = referencedId(value);
    bool matches = shape.kind == ValueKind::Reference && id.has_value() && *id == rowId && value.is_object();
    if (matches && !found.ok()) {
      found = keyOfReference(value);
    }
  });
  return found;
}

Status assignReferenceKeys(const TableDescriptor& table, Json& written, const RowKeyResolver& keyFor,
                           CodecError& error) {
  Status status = Status::Ok;
  walkContentLeaves(*table.model, written, [&](const ValueShape& shape, Json& value, uint32_t ordinal) {
    if (shape.kind == ValueKind::Reference && status == Status::Ok) {
      status = assignReferenceKey(table, shape, value, ordinal, keyFor, error);
    }
  });
  return status;
}

void removeReferenceKeys(const ModelDescriptor& model, Json& content) {
  walkContentLeaves(model, content, [](const ValueShape& shape, Json& value, uint32_t) {
    std::optional<std::string> id = referencedId(value);
    if (shape.kind == ValueKind::Reference && id.has_value()) {
      value = *id;
    }
  });
}

}  // namespace nw
