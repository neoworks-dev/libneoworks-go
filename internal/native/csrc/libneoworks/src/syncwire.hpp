#pragma once

#include <optional>
#include <string>
#include <vector>

#include "accesslog.hpp"
#include "grant.hpp"
#include "node.hpp"

namespace nw {

// Wire formats of contract section 7. Parsers are total: malformed input yields a
// status, never undefined behaviour, and one bad entry never discards its siblings.

struct PullPage {
  std::vector<Node> nodes;
  std::vector<AccessGrant> grants;
  std::vector<AccessLogEntry> accessLog;
  // Ids of rows that left this holder's reach since the request's cursor.
  std::vector<std::string> leftReach;
  std::string cursor;
  bool hasMore = false;
  size_t malformedEntries = 0;
};
Result<PullPage> parsePullResponse(ByteView body);

struct PushResult {
  enum class Outcome { Ok, Conflict, Forbidden };
  std::string id;
  Outcome outcome = Outcome::Forbidden;
  uint64_t seq = 0;
  // Set on a forbidden write of a row older than its owner's finished migration
  // (reason "schema_outdated"): the schema version the app has to update to.
  std::optional<std::string> requiredSchemaVersion;
};
// GET /nodes/{id}/access-log: {"entries": [...]} or a bare array.
Result<std::vector<AccessLogEntry>> parseAccessLogResponse(ByteView body);
Result<std::vector<PushResult>> parsePushResponse(ByteView body);
Bytes buildPushRequest(const std::vector<Node>& nodes);

struct PresignedUrl {
  uint32_t index = 0;
  std::string url;
};
Result<std::vector<PresignedUrl>> parsePresignResponse(ByteView body);
Bytes buildPresignRequest(const std::string& nodeId, const std::string& objectId, bool upload,
                          const std::vector<uint32_t>& chunkIndexes);

}  // namespace nw
