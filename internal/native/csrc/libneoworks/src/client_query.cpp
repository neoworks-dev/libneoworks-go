#include <algorithm>

#include "client.hpp"
#include "query.hpp"
#include "query_fields.hpp"
#include "schema_values.hpp"
#include "tlv.hpp"
#include "timeutil.hpp"

namespace nw {

namespace {

constexpr size_t kSafetyCodeGroups = 6;

std::optional<int64_t> millisOf(const IndexedNode& entry, uint32_t ordinal) {
  auto found = entry.values.find(ordinal);
  if (found == entry.values.end()) {
    return std::nullopt;
  }
  const WideInteger& integer = found->second.integer;
  if (integer.negative) {
    return -static_cast<int64_t>(integer.magnitude);
  }
  return static_cast<int64_t>(integer.magnitude);
}

bool overlaps(int64_t start, int64_t end, int64_t rangeStart, int64_t rangeEnd) {
  return start < rangeEnd && std::max(end, start + 1) > rangeStart;
}

const NodeDescriptor* itemDescriptorOf(const SchemaDescriptor* schema) {
  if (schema == nullptr) {
    return nullptr;
  }
  return schema->nodeByKind("item");
}

// The node kind a query runs over: "item" unless the query asks for "asset" with its "model" member.
Result<std::string> queriedModelOf(const Json& query, CodecError& error) {
  auto requested = query.find("model");
  if (!query.is_object() || requested == query.end()) {
    return std::string("item");
  }
  if (requested->is_string() && (*requested == "item" || *requested == "asset")) {
    return requested->get<std::string>();
  }
  error.status = Status::InvalidArgument;
  error.path = "model";
  error.reason = "must be \"item\" or \"asset\"";
  return Status::InvalidArgument;
}

}  // namespace

Result<std::vector<std::string>> Client::query(const std::string& collection, const Json& query) {
  lastContentError_ = CodecError{};
  const SchemaDescriptor* schema = descriptorFor(collection);
  if (schema == nullptr) {
    lastContentError_.status = Status::InvalidState;
    lastContentError_.path = collection;
    lastContentError_.reason = "no confirmed descriptor for the collection";
    return Status::InvalidState;
  }
  Result<std::string> model = queriedModelOf(query, lastContentError_);
  if (!model.ok()) {
    return model.status();
  }
  const NodeDescriptor* queried = schema->nodeByKind(model.value());
  if (queried == nullptr) {
    lastContentError_.status = Status::InvalidArgument;
    lastContentError_.path = collection;
    lastContentError_.reason = "the schema has no " + model.value() + " model";
    return Status::InvalidArgument;
  }
  const NodeDescriptor* container = schema->nodeByKind("container");
  const ModelDescriptor* containerModel = nullptr;
  if (container != nullptr) {
    containerModel = container->model;
  }
  Json conditions = query;
  if (conditions.is_object()) {
    conditions.erase("model");
  }
  Result<Query> compiled = compileQuery(conditions, *queried->model, containerModel, lastContentError_);
  if (!compiled.ok()) {
    return compiled.status();
  }
  return runQuery(compiled.value(), index_, collection, model.value());
}

std::vector<std::string> Client::queryRange(const std::string& collection, int64_t rangeStart, int64_t rangeEnd) {
  std::vector<std::string> matches;
  const NodeDescriptor* descriptor = itemDescriptorOf(descriptorFor(collection));
  if (descriptor == nullptr || !descriptor->timeRange.has_value()) {
    return matches;
  }
  for (const auto& [nodeId, entry] : index_.nodesOf(collection)) {
    std::optional<int64_t> start = millisOf(entry, descriptor->timeRange->start);
    std::optional<int64_t> end = millisOf(entry, descriptor->timeRange->end);
    bool inRange = start.has_value() && end.has_value() && overlaps(*start, *end, rangeStart, rangeEnd);
    if (entry.model == "item" && inRange) {
      matches.push_back(nodeId);
    }
  }
  return matches;
}

std::vector<std::string> Client::search(const std::string& collection, const std::string& needle) {
  std::vector<std::string> matches;
  if (itemDescriptorOf(descriptorFor(collection)) == nullptr) {
    return matches;
  }
  std::string lowered = lowercaseAscii(needle);
  for (const auto& [nodeId, entry] : index_.nodesOf(collection)) {
    bool found = std::any_of(entry.searchTexts.begin(), entry.searchTexts.end(),
                             [&](const std::string& text) { return text.find(lowered) != std::string::npos; });
    if (entry.model == "item" && found) {
      matches.push_back(nodeId);
    }
  }
  return matches;
}

PublicIdentity Client::ownIdentity() const {
  if (account_.has_value()) {
    return account_->publicIdentity();
  }
  return PublicIdentity();
}

namespace {

bool sameKeys(const IdentityVersion& version, const Bytes& signPub, const Bytes& encPub) {
  return version.signPub == signPub && version.encPub == encPub;
}

// A pin with a history is anchored on its version 1; one without on the identity it holds,
// which must then appear somewhere in the chain.
bool chainContinuesPin(const PinnedIdentity& pin, const std::vector<IdentityVersion>& history) {
  if (!pin.history.empty()) {
    return sameKeys(history.front(), pin.history.front().signPub, pin.history.front().encPub);
  }
  for (const IdentityVersion& version : history) {
    if (sameKeys(version, pin.identity.signPub, pin.identity.encPub)) {
      return true;
    }
  }
  return false;
}

}  // namespace

PinState Client::checkPin(const PublicIdentity& identity, const std::vector<IdentityVersion>& history) const {
  const PinnedIdentity* pinned = database_->findPin(identity.userId);
  if (pinned == nullptr) {
    return PinState::New;
  }
  bool unchanged = pinned->identity.encPub == identity.encPub && pinned->identity.signPub == identity.signPub;
  if (unchanged) {
    return PinState::Match;
  }
  bool rotated = !history.empty() && verifyHistoryEndsAt(identity, history) == Status::Ok &&
                 chainContinuesPin(*pinned, history);
  if (rotated) {
    return PinState::Match;
  }
  return PinState::Changed;
}

Status Client::pinIdentity(const PublicIdentity& identity, const std::vector<IdentityVersion>& history) {
  Status valid = verifyPublicIdentity(identity);
  if (valid != Status::Ok) {
    return valid;
  }
  if (!history.empty()) {
    Status chained = verifyHistoryEndsAt(identity, history);
    if (chained != Status::Ok) {
      return chained;
    }
  }
  PinState state = checkPin(identity, history);
  if (state == PinState::Changed) {
    return Status::Conflict;
  }
  const PinnedIdentity* existing = database_->findPin(identity.userId);
  if (state == PinState::Match) {
    if (history.empty()) {
      return Status::Ok;
    }
    if (!chainContinuesPin(*existing, history)) {
      return Status::Conflict;
    }
    if (history.size() < existing->history.size()) {
      return Status::Ok;
    }
    PinnedIdentity followed = *existing;
    followed.identity = identity;
    followed.history = history;
    return database_->putPin(followed);
  }
  PinnedIdentity pin;
  pin.identity = identity;
  pin.history = history;
  pin.pinnedAt = nowText();
  return database_->putPin(pin);
}

Status Client::acceptIdentityChange(const PublicIdentity& identity, const std::vector<IdentityVersion>& history) {
  Status valid = verifyPublicIdentity(identity);
  if (valid != Status::Ok) {
    return valid;
  }
  if (!history.empty()) {
    Status chained = verifyHistoryEndsAt(identity, history);
    if (chained != Status::Ok) {
      return chained;
    }
  }
  PinnedIdentity pin;
  pin.identity = identity;
  pin.history = history;
  pin.userVerified = false;
  pin.pinnedAt = nowText();
  return database_->putPin(pin);
}

Status Client::markIdentityVerified(const std::string& userId) {
  const PinnedIdentity* existing = database_->findPin(userId);
  if (existing == nullptr) {
    return Status::NotFound;
  }
  PinnedIdentity updated = *existing;
  updated.userVerified = true;
  return database_->putPin(updated);
}

Result<SafetyCode> Client::safetyCode(const std::string& userId) const {
  const PinnedIdentity* pinned = database_->findPin(userId);
  if (pinned == nullptr) {
    return Status::NotFound;
  }
  Bytes digest = hash(TlvWriter("nw-safety-v1")
                          .text(userId)
                          .bytes(pinned->anchorEncPub())
                          .bytes(pinned->anchorSignPub())
                          .finish());
  SafetyCode code;
  code.userId = userId;
  for (size_t group = 0; group < kSafetyCodeGroups; ++group) {
    uint32_t value = decodeU32(ByteView(digest).subspan(group * 4, 4)).value();
    char digits[8];
    static_cast<void>(std::snprintf(digits, sizeof(digits), "%05u", value % 100000u));
    if (group > 0) {
      code.digits += " ";
    }
    code.digits += digits;
  }
  return code;
}

std::optional<Client::LookupNeed> Client::lookupNeededFor(const Node& node) const {
  if (node.authorType == "user") {
    if (database_->findPin(node.authorId) == nullptr) {
      return LookupNeed{LookupNeed::Kind::Identity, node.authorId};
    }
    return std::nullopt;
  }
  if (!node.certId.has_value() || database_->findCertificate(*node.certId) != nullptr) {
    return std::nullopt;
  }
  return LookupNeed{LookupNeed::Kind::Certificate, *node.certId};
}

Status Client::verifyRemoteNode(const Node& node) const {
  if (validateNodeShape(node) != Status::Ok) {
    return Status::Malformed;
  }
  if (node.authorType == "user") {
    const PinnedIdentity* author = database_->findPin(node.authorId);
    if (author == nullptr) {
      return Status::NotFound;
    }
    for (const IdentityVersion& key : author->verificationKeys()) {
      if (verifyNodeWrite(key.signPub, node)) {
        return Status::Ok;
      }
    }
    return Status::AuthenticationFailed;
  }
  const StoredCertificate* stored = database_->findCertificate(*node.certId);
  if (stored == nullptr) {
    return Status::NotFound;
  }
  return verifyInstallAuthoredNode(stored->certificate, node);
}

namespace {

Json asNodeJson(Json version, const Node& current) {
  version["id"] = version.value("nodeId", std::string());
  version["ownerId"] = current.ownerId;
  version["updatedAt"] = version.value("createdAt", std::string());
  return version;
}

}  // namespace

Result<VersionRead> Client::readVersion(const Json& version) {
  if (!version.is_object()) {
    return Status::Malformed;
  }
  const Node* current = database_->findNode(version.value("nodeId", std::string()));
  if (current == nullptr) {
    return Status::NotFound;
  }
  Result<Node> parsed = nodeFromJson(asNodeJson(version, *current));
  if (!parsed.ok()) {
    return parsed.status();
  }
  const Node& old = parsed.value();
  if (old.collection != current->collection || old.deleted) {
    return Status::NotFound;
  }
  std::optional<SymmetricKey> nodeKey = keyring_.findNodeKey(old.id, old.epoch);
  if (!nodeKey.has_value()) {
    return Status::NotFound;
  }
  Result<Json> content = readContent(old, &*nodeKey);
  if (content.status() == Status::AuthenticationFailed) {
    return Status::AuthenticationFailed;
  }
  if (!content.ok()) {
    return content.status();
  }
  Status verification = verifyRemoteNode(old);
  if (verification == Status::AuthenticationFailed || verification == Status::Malformed) {
    return Status::AuthenticationFailed;
  }
  VersionRead read;
  read.content = content.take();
  read.verified = verification == Status::Ok;
  read.authorType = old.authorType;
  read.authorId = old.authorId;
  read.seq = old.seq;
  read.deleted = old.deleted;
  read.createdAt = old.createdAt;
  return read;
}

}  // namespace nw
