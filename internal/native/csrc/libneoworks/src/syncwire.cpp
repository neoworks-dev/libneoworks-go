#include "syncwire.hpp"

namespace nw {

namespace {

std::optional<Json> parseBody(ByteView body) {
  return parseJson(std::string_view(reinterpret_cast<const char*>(body.data()), body.size()));
}

void collectNodes(const Json& entries, PullPage& page) {
  for (const Json& entry : entries) {
    Result<Node> node = nodeFromJson(entry);
    if (node.ok() && validateNodeShape(node.value()) == Status::Ok) {
      page.nodes.push_back(node.take());
    } else {
      ++page.malformedEntries;
    }
  }
}

void collectGrants(const Json& entries, PullPage& page) {
  for (const Json& entry : entries) {
    Result<AccessGrant> grant = grantFromJson(entry);
    if (grant.ok()) {
      page.grants.push_back(grant.take());
    } else {
      ++page.malformedEntries;
    }
  }
}

void collectEntries(const Json& entries, PullPage& page) {
  for (const Json& item : entries) {
    Result<AccessLogEntry> entry = entryFromJson(item);
    if (entry.ok()) {
      page.accessLog.push_back(entry.take());
    } else {
      ++page.malformedEntries;
    }
  }
}

void collectLeftReach(const Json& ids, PullPage& page) {
  for (const Json& id : ids) {
    if (id.is_string()) {
      page.leftReach.push_back(id.get<std::string>());
    } else {
      ++page.malformedEntries;
    }
  }
}

std::optional<PushResult::Outcome> outcomeFromText(const std::string& status) {
  if (status == "ok") {
    return PushResult::Outcome::Ok;
  }
  if (status == "conflict") {
    return PushResult::Outcome::Conflict;
  }
  if (status == "forbidden") {
    return PushResult::Outcome::Forbidden;
  }
  return std::nullopt;
}

std::optional<std::string> requiredSchemaVersionOf(const Json& entry) {
  if (readString(entry, "reason") != std::optional<std::string>("schema_outdated")) {
    return std::nullopt;
  }
  return readString(entry, "requiredVersion");
}

// The contract leaves the cursor type open: accept an opaque string or a number.
std::optional<std::string> readCursor(const Json& json) {
  std::optional<std::string> text = readString(json, "cursor");
  if (text.has_value()) {
    return text;
  }
  std::optional<uint64_t> number = readUnsigned(json, "cursor");
  if (number.has_value()) {
    return std::to_string(*number);
  }
  return std::nullopt;
}

}  // namespace

Result<PullPage> parsePullResponse(ByteView body) {
  std::optional<Json> json = parseBody(body);
  if (!json.has_value()) {
    return Status::Malformed;
  }
  const Json* nodes = readArray(*json, "nodes");
  const Json* grants = readArray(*json, "grants");
  std::optional<std::string> cursor = readCursor(*json);
  std::optional<bool> hasMore = readBool(*json, "hasMore");
  if (nodes == nullptr || grants == nullptr || !cursor || !hasMore) {
    return Status::Malformed;
  }
  PullPage page;
  page.cursor = *cursor;
  page.hasMore = *hasMore;
  collectNodes(*nodes, page);
  collectGrants(*grants, page);
  const Json* accessLog = readArray(*json, "accessLog");
  if (accessLog != nullptr) {
    collectEntries(*accessLog, page);
  }
  const Json* leftReach = readArray(*json, "leftReach");
  if (leftReach != nullptr) {
    collectLeftReach(*leftReach, page);
  }
  return page;
}

Result<std::vector<AccessLogEntry>> parseAccessLogResponse(ByteView body) {
  std::optional<Json> json = parseBody(body);
  if (!json.has_value()) {
    return Status::Malformed;
  }
  const Json* list = nullptr;
  if (json->is_array()) {
    list = &*json;
  } else {
    list = readArray(*json, "entries");
  }
  if (list == nullptr) {
    return Status::Malformed;
  }
  std::vector<AccessLogEntry> entries;
  for (const Json& item : *list) {
    Result<AccessLogEntry> entry = entryFromJson(item);
    if (!entry.ok()) {
      return Status::Malformed;
    }
    entries.push_back(entry.take());
  }
  return entries;
}

Result<std::vector<PushResult>> parsePushResponse(ByteView body) {
  std::optional<Json> json = parseBody(body);
  if (!json.has_value()) {
    return Status::Malformed;
  }
  const Json* results = readArray(*json, "results");
  if (results == nullptr) {
    return Status::Malformed;
  }
  std::vector<PushResult> parsed;
  for (const Json& entry : *results) {
    std::optional<std::string> id = readString(entry, "id");
    std::optional<std::string> status = readString(entry, "status");
    if (!id || !status || !outcomeFromText(*status).has_value()) {
      return Status::Malformed;
    }
    PushResult result;
    result.id = *id;
    result.outcome = *outcomeFromText(*status);
    result.seq = readUnsigned(entry, "seq").value_or(0);
    result.requiredSchemaVersion = requiredSchemaVersionOf(entry);
    parsed.push_back(std::move(result));
  }
  return parsed;
}

Bytes buildPushRequest(const std::vector<Node>& nodes) {
  Json nodesJson = Json::array();
  for (const Node& node : nodes) {
    nodesJson.push_back(nodeToJson(node));
  }
  Json body = Json::object();
  body["nodes"] = std::move(nodesJson);
  return bytesOf(dumpCompact(body));
}

Result<std::vector<PresignedUrl>> parsePresignResponse(ByteView body) {
  std::optional<Json> json = parseBody(body);
  if (!json.has_value()) {
    return Status::Malformed;
  }
  const Json* urls = readArray(*json, "urls");
  if (urls == nullptr) {
    return Status::Malformed;
  }
  std::vector<PresignedUrl> parsed;
  for (const Json& entry : *urls) {
    std::optional<uint64_t> index = readUnsigned(entry, "index");
    std::optional<std::string> url = readString(entry, "url");
    if (!index || !url || *index > UINT32_MAX) {
      return Status::Malformed;
    }
    parsed.push_back(PresignedUrl{static_cast<uint32_t>(*index), *url});
  }
  return parsed;
}

Bytes buildPresignRequest(const std::string& nodeId, const std::string& objectId, bool upload,
                          const std::vector<uint32_t>& chunkIndexes) {
  Json body = Json::object();
  body["nodeId"] = nodeId;
  body["objectId"] = objectId;
  body["op"] = "get";
  if (upload) {
    body["op"] = "put";
  }
  body["chunks"] = chunkIndexes;
  return bytesOf(dumpCompact(body));
}

}  // namespace nw
