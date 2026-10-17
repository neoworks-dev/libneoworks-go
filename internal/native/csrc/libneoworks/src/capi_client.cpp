#include "capi_internal.hpp"

namespace nw::capi {

namespace {

// ---- storage ----

Result<std::vector<std::tuple<std::string, std::string, Bytes>>> parseSnapshot(const uint8_t* data, size_t length) {
  std::vector<std::tuple<std::string, std::string, Bytes>> records;
  if (data == nullptr || length == 0) {
    return records;
  }
  TlvReader reader(ByteView(data, length));
  if (!reader.valid() || reader.context() != "nw-records-v1") {
    return Status::Malformed;
  }
  while (!reader.atEnd()) {
    std::optional<ByteView> kind = reader.nextField();
    std::optional<ByteView> key = reader.nextField();
    std::optional<ByteView> value = reader.nextField();
    if (!kind || !key || !value) {
      return Status::Malformed;
    }
    records.emplace_back(std::string(kind->begin(), kind->end()), std::string(key->begin(), key->end()),
                         Bytes(value->begin(), value->end()));
  }
  return records;
}

std::unique_ptr<RecordBackend> makeHostBackend(const nw_storage_callbacks& host, Status& failure) {
  auto snapshot = parseSnapshot(host.snapshot, host.snapshot_length);
  if (!snapshot.ok()) {
    failure = snapshot.status();
    return nullptr;
  }
  auto records = std::make_shared<std::vector<std::tuple<std::string, std::string, Bytes>>>(snapshot.take());
  RecordCallbacks callbacks;
  callbacks.put = [host](std::string_view kind, std::string_view key, ByteView value) {
    if (host.put == nullptr) {
      return Status::Ok;
    }
    int status = host.put(host.user, std::string(kind).c_str(), std::string(key).c_str(), value.data(), value.size());
    return static_cast<Status>(status);
  };
  callbacks.remove = [host](std::string_view kind, std::string_view key) {
    if (host.remove == nullptr) {
      return Status::Ok;
    }
    return static_cast<Status>(host.remove(host.user, std::string(kind).c_str(), std::string(key).c_str()));
  };
  callbacks.clear = [host]() {
    if (host.clear == nullptr) {
      return Status::Ok;
    }
    return static_cast<Status>(host.clear(host.user));
  };
  callbacks.loadAll = [records](const RecordBackend::Visitor& visitor) {
    for (const auto& [kind, key, value] : *records) {
      visitor(kind, key, value);
    }
  };
  return makeCallbackBackend(std::move(callbacks));
}

std::unique_ptr<RecordBackend> makeBackendFor(const char* sqlitePath, const nw_storage_callbacks* callbacks,
                                              Status& failure) {
  if (sqlitePath != nullptr) {
#if defined(NW_HAVE_SQLITE)
    std::unique_ptr<RecordBackend> backend = makeSqliteBackend(sqlitePath);
    if (backend == nullptr) {
      failure = Status::IoFailure;
    }
    return backend;
#else
    failure = Status::Unsupported;
    return nullptr;
#endif
  }
  if (callbacks != nullptr) {
    return makeHostBackend(*callbacks, failure);
  }
  return makeMemoryBackend();
}

Result<std::unique_ptr<LocalDatabase>> openDatabase(const char* sqlitePath, const nw_storage_callbacks* callbacks,
                                                    SymmetricKey storeKey) {
  Status failure = Status::Ok;
  std::unique_ptr<RecordBackend> backend = makeBackendFor(sqlitePath, callbacks, failure);
  if (backend == nullptr) {
    return failure;
  }
  return LocalDatabase::open(std::move(backend), std::move(storeKey));
}

// ---- JSON shapes ----

Json nodeSummary(Client& client, const LocalNode& local) {
  const Node& node = local.node;
  Json json = Json::object();
  json["id"] = node.id;
  json["parentId"] = Json(nullptr);
  if (node.parentId.has_value()) {
    json["parentId"] = *node.parentId;
  }
  json["ownerId"] = node.ownerId;
  json["collection"] = node.collection;
  json["kind"] = node.kind;
  json["epoch"] = node.epoch;
  json["deleted"] = node.deleted;
  json["seq"] = node.seq;
  json["baseSeq"] = node.baseSeq;
  json["authorType"] = node.authorType;
  json["authorId"] = node.authorId;
  json["createdAt"] = node.createdAt;
  json["updatedAt"] = node.updatedAt;
  json["dirty"] = local.dirty;
  json["rejected"] = local.rejected;
  json["role"] = client.effectiveRole(node.id);
  json["targetId"] = Json(nullptr);
  json["targetRole"] = Json(nullptr);
  if (node.targetId.has_value()) {
    json["targetId"] = *node.targetId;
    json["targetRole"] = *node.targetRole;
  }
  json["files"] = filesToJson(node.files);
  return json;
}

Json rotationReportJson(const RotationReport& report) {
  Json json = Json::object();
  json["rotatedNodeIds"] = report.rotatedNodeIds;
  return json;
}

// A public identity with the optional `history` array of GET /users/{id}/identity-keys.
struct ParsedIdentity {
  PublicIdentity identity;
  std::vector<IdentityVersion> history;
};

Result<ParsedIdentity> parseIdentityJson(const Json& json) {
  Result<PublicIdentity> identity = publicIdentityFromJson(json);
  if (!identity.ok()) {
    return identity.status();
  }
  ParsedIdentity parsed;
  parsed.identity = identity.take();
  if (json.contains("history")) {
    Result<std::vector<IdentityVersion>> history = identityHistoryFromJson(json.at("history"));
    if (!history.ok()) {
      return history.status();
    }
    parsed.history = history.take();
  }
  return parsed;
}

Result<ParsedIdentity> parseIdentityText(const char* text) {
  std::optional<Json> json = parseText(text);
  if (!json.has_value()) {
    return Status::Malformed;
  }
  return parseIdentityJson(*json);
}

Json requestMeta(const HttpRequest& request) {
  Json meta = Json::object();
  meta["method"] = request.method;
  meta["url"] = request.url;
  meta["isApi"] = request.isApi;
  meta["contentType"] = request.contentType;
  return meta;
}

Json reportJson(const SyncReport& report) {
  Json json = Json::object();
  json["pushedNodes"] = report.pushedNodes;
  json["pulledNodes"] = report.pulledNodes;
  json["appliedNodes"] = report.appliedNodes;
  json["rebasedNodes"] = report.rebasedNodes;
  json["lostLocalEdits"] = report.lostLocalEdits;
  json["unverifiableNodes"] = report.unverifiableNodes;
  json["malformedEntries"] = report.malformedEntries;
  json["grantsApplied"] = report.grantsApplied;
  json["sharingOperationsSent"] = report.sharingOperationsSent;
  json["fullResync"] = report.fullResync;
  json["forbiddenNodeIds"] = report.forbiddenNodeIds;
  json["integrityFailures"] = report.integrityFailures;
  Json conflicts = Json::array();
  for (const PinConflict& conflict : report.pinConflicts) {
    conflicts.push_back(conflict.userId);
  }
  json["pinConflicts"] = conflicts;
  json["failure"] = nw_status_name(static_cast<int>(report.failure));
  json["failureCode"] = static_cast<int>(report.failure);
  return json;
}

int publishClient(std::unique_ptr<Client> client, nw_client** out) {
  *out = new nw_client{std::move(client)};
  return kOk;
}

bool hasArguments(nw_client* client, const void* a) { return client != nullptr && a != nullptr; }

}  // namespace

}  // namespace nw::capi

using namespace nw;
using namespace nw::capi;

namespace {

Result<ShareRequest> parseShareRequest(nw_client* client, const Json& json) {
  ShareRequest request;
  request.nodeId = readString(json, "nodeId").value_or("");
  request.principalType = readString(json, "principalType").value_or("");
  request.principalId = readString(json, "principalId").value_or("");
  request.role = readString(json, "role").value_or("");
  if (json.contains("facets") && json.at("facets").is_array()) {
    std::vector<uint32_t> facets;
    for (const Json& facet : json.at("facets")) {
      if (!facet.is_number_unsigned()) {
        return Status::Malformed;
      }
      facets.push_back(facet.get<uint32_t>());
    }
    request.facets = facets;
  }
  if (request.principalType == "user") {
    Result<ParsedIdentity> recipient = parseIdentityJson(json.value("recipient", Json::object()));
    if (!recipient.ok() || recipient.value().identity.userId != request.principalId) {
      return Status::Malformed;
    }
    Status pinned = client->value->pinIdentity(recipient.value().identity, recipient.value().history);
    if (pinned != Status::Ok) {
      return pinned;
    }
    request.principalEncPub = recipient.value().identity.encPub;
    return request;
  }
  std::optional<Bytes> encPub = readBytes(json, "recipientEncPub");
  if (!encPub.has_value()) {
    return Status::Malformed;
  }
  request.principalEncPub = std::move(*encPub);
  return request;
}

}  // namespace

extern "C" {

int nw_client_open_install(const nw_install* install, const char* sqlite_path,
                           const nw_storage_callbacks* callbacks, nw_client** out) {
  if (install == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<std::unique_ptr<LocalDatabase>> database =
        openDatabase(sqlite_path, callbacks, install->value.storeKey.clone());
    if (!database.ok()) {
      return code(database.status());
    }
    return publishClient(Client::forInstall(duplicateInstall(install->value), database.take()), out);
  });
}

int nw_client_open_account(const nw_account* account, const char* sqlite_path,
                           const nw_storage_callbacks* callbacks, nw_client** out) {
  if (account == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<std::unique_ptr<LocalDatabase>> database = openDatabase(sqlite_path, callbacks, account->value.storeKey());
    if (!database.ok()) {
      return code(database.status());
    }
    return publishClient(Client::forAccount(account->value.duplicate(), database.take()), out);
  });
}

void nw_client_free(nw_client* client) { delete client; }

int nw_client_accept_grant(nw_client* client, const char* neoworks_grant_json, const char* owner_identity_json) {
  if (client == nullptr || neoworks_grant_json == nullptr || owner_identity_json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> grant = parseText(neoworks_grant_json);
    Result<ParsedIdentity> owner = parseIdentityText(owner_identity_json);
    if (!grant.has_value() || !owner.ok()) {
      return code(Status::Malformed);
    }
    return code(client->value->acceptGrantBundle(*grant, owner.value().identity, owner.value().history));
  });
}

int nw_identity_verify_history(const char* identity_json) {
  if (identity_json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<ParsedIdentity> parsed = parseIdentityText(identity_json);
    if (!parsed.ok()) {
      return code(parsed.status());
    }
    return code(verifyHistoryEndsAt(parsed.value().identity, parsed.value().history));
  });
}

int nw_client_store_certificate(nw_client* client, const uint8_t* certificate, size_t certificate_length,
                                const uint8_t* signature, size_t signature_length) {
  if (client == nullptr || certificate == nullptr || signature == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Bytes certificateBytes(certificate, certificate + certificate_length);
    Bytes signatureBytes(signature, signature + signature_length);
    return code(client->value->storeCertificate(certificateBytes, signatureBytes));
  });
}

int nw_client_store_renewal_certificate(nw_client* client, const uint8_t* renewal, size_t renewal_length,
                                        const uint8_t* signature, size_t signature_length) {
  if (client == nullptr || renewal == nullptr || signature == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Bytes renewalBytes(renewal, renewal + renewal_length);
    Bytes signatureBytes(signature, signature + signature_length);
    return code(client->value->storeRenewalCertificate(renewalBytes, signatureBytes));
  });
}

int nw_client_register_descriptor(nw_client* client, const char* collection, const char* descriptor_json,
                                  const char* schema_version, nw_buffer* check_json) {
  if (!hasArguments(client, collection) || descriptor_json == nullptr || schema_version == nullptr ||
      check_json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<std::optional<DescriptorCheck>> check =
        client->value->registerDescriptor(collection, descriptor_json, schema_version);
    if (!check.ok()) {
      return code(check.status());
    }
    if (!check.value().has_value()) {
      return fillJson(check_json, Json(nullptr));
    }
    Json result = Json::object();
    result["descriptorHash"] = check.value()->descriptorHash;
    result["method"] = check.value()->request.method;
    result["url"] = check.value()->request.url;
    result["isApi"] = check.value()->request.isApi;
    return fillJson(check_json, result);
  });
}

int nw_client_complete_descriptor_check(nw_client* client, const char* collection, int http_status,
                                        const uint8_t* body, size_t body_length) {
  if (!hasArguments(client, collection) || (body == nullptr && body_length != 0)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    HttpResponse response;
    response.status = http_status;
    if (body != nullptr) {
      response.body.assign(body, body + body_length);
    }
    return code(client->value->completeDescriptorCheck(collection, response));
  });
}

int nw_client_last_content_error(nw_client* client, nw_buffer* json) {
  if (client == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    const CodecError& error = client->value->lastContentError();
    if (error.status == Status::Ok) {
      return fillJson(json, Json(nullptr));
    }
    Json result = Json::object();
    result["status"] = static_cast<int>(error.status);
    result["path"] = error.path;
    result["reason"] = error.reason;
    return fillJson(json, result);
  });
}

int nw_client_create_node(nw_client* client, const char* request_json, nw_buffer* node_id) {
  if (!hasArguments(client, request_json) || node_id == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> json = parseText(request_json);
    if (!json.has_value()) {
      return code(Status::Malformed);
    }
    CreateNodeRequest request;
    request.parentId = readString(*json, "parentId");
    request.collection = readString(*json, "collection").value_or("");
    request.kind = readString(*json, "kind").value_or("");
    if (json->contains("content")) {
      request.content = json->at("content");
    }
    Result<std::string> created = client->value->createNode(request);
    if (!created.ok()) {
      return code(created.status());
    }
    return fillText(node_id, created.value());
  });
}

int nw_client_create_shortcut(nw_client* client, const char* request_json, nw_buffer* node_id) {
  if (!hasArguments(client, request_json) || node_id == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> json = parseText(request_json);
    if (!json.has_value()) {
      return code(Status::Malformed);
    }
    CreateShortcutRequest request;
    request.parentId = readString(*json, "parentId").value_or("");
    request.targetId = readString(*json, "targetId").value_or("");
    request.targetRole = readString(*json, "targetRole").value_or("");
    Result<std::string> created = client->value->createShortcut(request);
    if (!created.ok()) {
      return code(created.status());
    }
    return fillText(node_id, created.value());
  });
}

int nw_client_update_node(nw_client* client, const char* request_json) {
  if (!hasArguments(client, request_json)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> json = parseText(request_json);
    if (!json.has_value()) {
      return code(Status::Malformed);
    }
    UpdateNodeRequest request;
    request.nodeId = readString(*json, "nodeId").value_or("");
    if (json->contains("changes")) {
      request.changes = json->at("changes");
    }
    return code(client->value->updateNode(request));
  });
}

int nw_client_delete_node(nw_client* client, const char* node_id, int recursive) {
  if (!hasArguments(client, node_id)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return code(client->value->deleteNode(node_id, recursive != 0)); });
}

int nw_client_read_node(nw_client* client, const char* node_id, nw_buffer* json) {
  if (!hasArguments(client, node_id) || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Json> content = client->value->readNode(node_id);
    if (!content.ok()) {
      return code(content.status());
    }
    return fillJson(json, content.value());
  });
}

int nw_client_read_version(nw_client* client, const char* version_json, nw_buffer* json) {
  if (!hasArguments(client, version_json) || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> version = parseText(version_json);
    if (!version.has_value()) {
      return code(Status::Malformed);
    }
    Result<VersionRead> read = client->value->readVersion(*version);
    if (!read.ok()) {
      return code(read.status());
    }
    Json result = Json::object();
    result["content"] = read.value().content;
    result["verified"] = read.value().verified;
    result["authorType"] = read.value().authorType;
    result["authorId"] = read.value().authorId;
    result["seq"] = read.value().seq;
    result["deleted"] = read.value().deleted;
    result["createdAt"] = read.value().createdAt;
    return fillJson(json, result);
  });
}

int nw_client_get_node(nw_client* client, const char* node_id, nw_buffer* json) {
  if (!hasArguments(client, node_id) || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    const LocalNode* local = client->value->database().findLocal(node_id);
    if (local == nullptr) {
      return code(Status::NotFound);
    }
    return fillJson(json, nodeSummary(*client->value, *local));
  });
}

int nw_client_list_nodes(nw_client* client, const char* parent_id, const char* collection, nw_buffer* json) {
  if (client == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    LocalDatabase& database = client->value->database();
    std::vector<std::string> ids;
    if (parent_id != nullptr) {
      ids = database.childrenOf(parent_id);
    } else if (collection != nullptr) {
      ids = database.nodesInCollection(collection);
    } else {
      ids = database.allNodeIds();
    }
    Json list = Json::array();
    for (const std::string& id : ids) {
      const LocalNode* local = database.findLocal(id);
      bool matchesCollection = collection == nullptr || local->node.collection == collection;
      if (local->node.deleted || !matchesCollection) {
        continue;
      }
      list.push_back(nodeSummary(*client->value, *local));
    }
    return fillJson(json, list);
  });
}

int nw_client_effective_role(nw_client* client, const char* node_id, nw_buffer* role) {
  if (!hasArguments(client, node_id) || role == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return fillText(role, client->value->effectiveRole(node_id)); });
}

int nw_client_query_range(nw_client* client, const char* collection, int64_t start_unix_millis,
                          int64_t end_unix_millis, nw_buffer* json) {
  if (!hasArguments(client, collection) || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded(
      [&] { return fillJson(json, client->value->queryRange(collection, start_unix_millis, end_unix_millis)); });
}

int nw_client_search(nw_client* client, const char* collection, const char* needle, nw_buffer* json) {
  if (!hasArguments(client, collection) || needle == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return fillJson(json, client->value->search(collection, needle)); });
}

int nw_client_query(nw_client* client, const char* collection, const char* query_json, nw_buffer* json) {
  if (!hasArguments(client, collection) || query_json == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> query = parseText(query_json);
    if (!query.has_value()) {
      return code(Status::Malformed);
    }
    Result<std::vector<std::string>> ids = client->value->query(collection, *query);
    if (!ids.ok()) {
      return code(ids.status());
    }
    return fillJson(json, ids.value());
  });
}

int nw_client_wipe(nw_client* client) {
  if (client == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    client->value->keyring().clear();
    return code(client->value->database().wipe());
  });
}

/* ---- pins ---- */

int nw_client_check_pin(nw_client* client, const char* identity_json, int* state) {
  if (!hasArguments(client, identity_json) || state == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<ParsedIdentity> identity = parseIdentityText(identity_json);
    if (!identity.ok()) {
      return code(identity.status());
    }
    *state = static_cast<int>(client->value->checkPin(identity.value().identity, identity.value().history));
    return kOk;
  });
}

int nw_client_pin_identity(nw_client* client, const char* identity_json) {
  if (!hasArguments(client, identity_json)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<ParsedIdentity> identity = parseIdentityText(identity_json);
    if (!identity.ok()) {
      return code(identity.status());
    }
    return code(client->value->pinIdentity(identity.value().identity, identity.value().history));
  });
}

int nw_client_accept_identity_change(nw_client* client, const char* identity_json) {
  if (!hasArguments(client, identity_json)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<ParsedIdentity> identity = parseIdentityText(identity_json);
    if (!identity.ok()) {
      return code(identity.status());
    }
    return code(client->value->acceptIdentityChange(identity.value().identity, identity.value().history));
  });
}

int nw_client_mark_verified(nw_client* client, const char* user_id) {
  if (!hasArguments(client, user_id)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return code(client->value->markIdentityVerified(user_id)); });
}

int nw_client_safety_code(nw_client* client, const char* user_id, nw_buffer* digits) {
  if (!hasArguments(client, user_id) || digits == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<SafetyCode> safety = client->value->safetyCode(user_id);
    if (!safety.ok()) {
      return code(safety.status());
    }
    return fillText(digits, safety.value().digits);
  });
}

int nw_client_list_pins(nw_client* client, nw_buffer* json) {
  if (client == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Json pins = Json::array();
    for (const PinnedIdentity& pin : client->value->database().allPins()) {
      Json entry = Json::object();
      entry["identity"] = publicIdentityToJson(pin.identity);
      entry["history"] = identityHistoryToJson(pin.history);
      entry["userVerified"] = pin.userVerified;
      entry["pinnedAt"] = pin.pinnedAt;
      pins.push_back(std::move(entry));
    }
    return fillJson(json, pins);
  });
}

/* ---- sharing ---- */


int nw_client_share_node(nw_client* client, const char* request_json, nw_buffer* grant_json) {
  if (!hasArguments(client, request_json) || grant_json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> json = parseText(request_json);
    if (!json.has_value()) {
      return code(Status::Malformed);
    }
    Result<ShareRequest> request = parseShareRequest(client, *json);
    if (!request.ok()) {
      return code(request.status());
    }
    Result<AccessGrant> grant = client->value->shareNode(request.value());
    if (!grant.ok()) {
      return code(grant.status());
    }
    return fillJson(grant_json, grantToJson(grant.value()));
  });
}

int nw_client_revoke_access(nw_client* client, const char* node_id, const char* principal_type,
                            const char* principal_id, nw_buffer* report_json) {
  bool valid = hasArguments(client, node_id) && principal_type != nullptr && principal_id != nullptr &&
               report_json != nullptr;
  if (!valid) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<RotationReport> report = client->value->revokeAccess(node_id, principal_type, principal_id);
    if (!report.ok()) {
      return code(report.status());
    }
    return fillJson(report_json, rotationReportJson(report.value()));
  });
}

int nw_client_list_grants(nw_client* client, const char* node_id, nw_buffer* json) {
  if (!hasArguments(client, node_id) || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Json grants = Json::array();
    for (const AccessGrant& grant : client->value->database().grantsForNode(node_id)) {
      grants.push_back(grantToJson(grant));
    }
    return fillJson(json, grants);
  });
}

int nw_client_create_link_key(nw_client* client, const char* node_id, nw_buffer* fragment_key,
                              nw_buffer* link_request_json) {
  if (!hasArguments(client, node_id) || fragment_key == nullptr || link_request_json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<std::string> fragment = client->value->createLinkFragment(node_id);
    if (!fragment.ok()) {
      return code(fragment.status());
    }
    int status = fillBuffer(fragment_key, viewOf(fragment.value()), true);
    if (status != NW_OK) {
      return status;
    }
    return fillJson(link_request_json, Json::object({{"nodeId", std::string(node_id)}}));
  });
}

int nw_client_record_link(nw_client* client, const char* node_id, const char* link_id) {
  if (!hasArguments(client, node_id) || link_id == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return code(client->value->recordLink(node_id, link_id)); });
}

int nw_client_list_links(nw_client* client, const char* node_id, nw_buffer* json) {
  if (!hasArguments(client, node_id) || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Json links = Json::array();
    for (const LinkRecord& link : client->value->linksFor(node_id)) {
      links.push_back(Json::object({{"nodeId", link.nodeId}, {"linkId", link.linkId}, {"createdAt", link.createdAt}}));
    }
    return fillJson(json, links);
  });
}

int nw_client_revoke_link(nw_client* client, const char* link_id, nw_buffer* report_json) {
  if (!hasArguments(client, link_id) || report_json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<RotationReport> report = client->value->revokeLink(link_id);
    if (!report.ok()) {
      return code(report.status());
    }
    return fillJson(report_json, rotationReportJson(report.value()));
  });
}

int nw_link_open(const char* pull_json, const char* fragment_key, nw_link_reader** out) {
  if (pull_json == nullptr || fragment_key == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<Json> json = parseText(pull_json);
    if (!json.has_value()) {
      return code(Status::Malformed);
    }
    Result<std::unique_ptr<LinkReader>> reader = LinkReader::open(*json, fragment_key);
    if (!reader.ok()) {
      return code(reader.status());
    }
    *out = new nw_link_reader{reader.take()};
    return kOk;
  });
}

int nw_link_list(nw_link_reader* reader, nw_buffer* json) {
  if (reader == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Json list = Json::array();
    for (const std::string& id : reader->value->nodeIds()) {
      const Node* node = reader->value->findNode(id);
      Json entry = Json::object();
      entry["id"] = node->id;
      entry["parentId"] = Json(nullptr);
      if (node->parentId.has_value()) {
        entry["parentId"] = *node->parentId;
      }
      entry["collection"] = node->collection;
      entry["kind"] = node->kind;
      entry["deleted"] = node->deleted;
      entry["updatedAt"] = node->updatedAt;
      entry["files"] = filesToJson(node->files);
      list.push_back(std::move(entry));
    }
    return fillJson(json, list);
  });
}

int nw_link_set_descriptor(nw_link_reader* reader, const char* collection, const char* descriptor_json) {
  if (reader == nullptr || collection == nullptr || descriptor_json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return code(reader->value->setDescriptor(collection, descriptor_json)); });
}

int nw_link_read_node(nw_link_reader* reader, const char* node_id, nw_buffer* json) {
  if (reader == nullptr || node_id == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    Result<Json> content = reader->value->readNode(node_id);
    if (!content.ok()) {
      return code(content.status());
    }
    return fillJson(json, content.value());
  });
}

void nw_link_free(nw_link_reader* reader) { delete reader; }

/* ---- sync ---- */

int nw_sync_begin(nw_client* client, nw_sync** out) {
  if (client == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    *out = new nw_sync{std::make_unique<SyncSession>(*client->value)};
    return kOk;
  });
}

int nw_sync_next_request(nw_sync* sync, int* has_request, nw_buffer* meta_json, nw_buffer* body) {
  if (sync == nullptr || has_request == nullptr || meta_json == nullptr || body == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    std::optional<HttpRequest> request = sync->value->nextRequest();
    *has_request = 0;
    clearBuffer(meta_json);
    clearBuffer(body);
    if (!request.has_value()) {
      return kOk;
    }
    *has_request = 1;
    int status = fillJson(meta_json, requestMeta(*request));
    if (status != NW_OK) {
      return status;
    }
    return fillBuffer(body, request->body, false);
  });
}

int nw_sync_handle_response(nw_sync* sync, int http_status, const uint8_t* body, size_t body_length) {
  if (sync == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    HttpResponse response;
    response.status = http_status;
    ByteView bodyView = viewOfInput(body, body_length);
    response.body.assign(bodyView.begin(), bodyView.end());
    return code(sync->value->handleResponse(response));
  });
}

int nw_sync_finished(const nw_sync* sync) {
  if (sync == nullptr) {
    return 1;
  }
  if (sync->value->finished()) {
    return 1;
  }
  return 0;
}

int nw_sync_report(const nw_sync* sync, nw_buffer* json) {
  if (sync == nullptr || json == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return fillJson(json, reportJson(sync->value->report())); });
}

void nw_sync_free(nw_sync* sync) { delete sync; }

/* ---- blobs ---- */

int nw_blob_upload_begin(nw_client* client, const char* node_id, const char* object_id, nw_blob_transfer** out) {
  if (!hasArguments(client, node_id) || object_id == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    auto transfer = BlobTransfer::beginUpload(*client->value, node_id, object_id);
    if (!transfer.ok()) {
      return code(transfer.status());
    }
    *out = new nw_blob_transfer{transfer.take()};
    return kOk;
  });
}

int nw_blob_download_begin(nw_client* client, const char* node_id, const char* object_id, nw_blob_transfer** out) {
  if (!hasArguments(client, node_id) || object_id == nullptr || out == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    auto transfer = BlobTransfer::beginDownload(*client->value, node_id, object_id);
    if (!transfer.ok()) {
      return code(transfer.status());
    }
    *out = new nw_blob_transfer{transfer.take()};
    return kOk;
  });
}

int nw_blob_link_download_begin(nw_link_reader* reader, const char* link_id, const char* node_id,
                                const char* object_id, nw_blob_transfer** out) {
  bool valid = reader != nullptr && link_id != nullptr && node_id != nullptr && object_id != nullptr && out != nullptr;
  if (!valid) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    auto transfer = BlobTransfer::beginLinkDownload(*reader->value, link_id, node_id, object_id);
    if (!transfer.ok()) {
      return code(transfer.status());
    }
    *out = new nw_blob_transfer{transfer.take()};
    return kOk;
  });
}

int nw_blob_next(nw_blob_transfer* transfer, int* state, uint32_t* chunk_index, nw_buffer* meta_json,
                 nw_buffer* body) {
  bool valid = transfer != nullptr && state != nullptr && chunk_index != nullptr && meta_json != nullptr &&
               body != nullptr;
  if (!valid) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    clearBuffer(meta_json);
    clearBuffer(body);
    BlobTransfer::State current = transfer->value->state();
    *chunk_index = transfer->value->chunkIndex();
    if (current == BlobTransfer::State::Failed) {
      return code(transfer->value->failure());
    }
    *state = 2;
    if (current == BlobTransfer::State::NeedChunk) {
      *state = 1;
    }
    if (current == BlobTransfer::State::ChunkReady) {
      *state = 3;
    }
    if (current != BlobTransfer::State::RequestReady) {
      return kOk;
    }
    *state = 0;
    int status = fillJson(meta_json, requestMeta(transfer->value->request()));
    if (status != NW_OK) {
      return status;
    }
    return fillBuffer(body, transfer->value->request().body, false);
  });
}

int nw_blob_provide_chunk(nw_blob_transfer* transfer, const uint8_t* plaintext, size_t length) {
  if (transfer == nullptr || (plaintext == nullptr && length > 0)) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] { return code(transfer->value->provideChunk(viewOfInput(plaintext, length))); });
}

int nw_blob_handle_response(nw_blob_transfer* transfer, int http_status, const uint8_t* body, size_t body_length) {
  if (transfer == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    HttpResponse response;
    response.status = http_status;
    ByteView bodyView = viewOfInput(body, body_length);
    response.body.assign(bodyView.begin(), bodyView.end());
    return code(transfer->value->handleResponse(response));
  });
}

int nw_blob_take_chunk(nw_blob_transfer* transfer, uint32_t* chunk_index, nw_buffer* plaintext) {
  if (transfer == nullptr || chunk_index == nullptr || plaintext == nullptr) {
    return NW_ERR_INVALID_ARGUMENT;
  }
  return guarded([&] {
    if (transfer->value->state() != BlobTransfer::State::ChunkReady) {
      return code(Status::InvalidState);
    }
    *chunk_index = transfer->value->chunkIndex();
    return fillBuffer(plaintext, transfer->value->takeChunk(), false);
  });
}

void nw_blob_free(nw_blob_transfer* transfer) { delete transfer; }

}  // extern "C"
