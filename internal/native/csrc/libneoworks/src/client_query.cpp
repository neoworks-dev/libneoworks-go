#include <algorithm>
#include <cctype>

#include "client.hpp"
#include "schema_values.hpp"
#include "tlv.hpp"
#include "timeutil.hpp"

namespace nw {

namespace {

constexpr size_t kSafetyCodeGroups = 6;

std::string lowercase(std::string text) {
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
  return text;
}

std::vector<std::string> searchableTexts(const NodeDescriptor& descriptor, const Json& content) {
  std::vector<std::string> texts;
  for (uint32_t ordinal : descriptor.searchable) {
    const FieldDescriptor* field = descriptor.model->fieldByOrdinal(ordinal);
    auto value = content.find(field->name);
    if (value == content.end()) {
      continue;
    }
    if (value->is_string()) {
      texts.push_back(value->get<std::string>());
      continue;
    }
    for (const Json& element : *value) {
      texts.push_back(element.get<std::string>());
    }
  }
  return texts;
}

std::optional<int64_t> timestampField(const ModelDescriptor& model, uint32_t ordinal, const Json& content) {
  auto value = content.find(model.fieldByOrdinal(ordinal)->name);
  if (value == content.end() || !value->is_string()) {
    return std::nullopt;
  }
  return timestampToMillis(value->get<std::string>());
}

bool overlaps(int64_t start, int64_t end, int64_t rangeStart, int64_t rangeEnd) {
  return start < rangeEnd && std::max(end, start + 1) > rangeStart;
}

bool isIndexedItem(const Node& node) { return node.kind == "item" && !node.deleted && !isShortcut(node); }

}  // namespace

std::vector<std::string> Client::queryRange(const std::string& collection, int64_t rangeStart, int64_t rangeEnd) {
  std::vector<std::string> matches;
  const SchemaDescriptor* schema = descriptorFor(collection);
  const NodeDescriptor* descriptor = nullptr;
  if (schema != nullptr) {
    descriptor = schema->nodeByKind("item");
  }
  if (descriptor == nullptr || !descriptor->timeRange.has_value()) {
    return matches;
  }
  for (const std::string& nodeId : database_->nodesInCollection(collection)) {
    Result<Json> content = Status::NotFound;
    if (isIndexedItem(*database_->findNode(nodeId))) {
      content = readNode(nodeId);
    }
    if (!content.ok()) {
      continue;
    }
    std::optional<int64_t> start = timestampField(*descriptor->model, descriptor->timeRange->start, content.value());
    std::optional<int64_t> end = timestampField(*descriptor->model, descriptor->timeRange->end, content.value());
    if (start.has_value() && end.has_value() && overlaps(*start, *end, rangeStart, rangeEnd)) {
      matches.push_back(nodeId);
    }
  }
  return matches;
}

std::vector<std::string> Client::search(const std::string& collection, const std::string& needle) {
  std::vector<std::string> matches;
  const SchemaDescriptor* schema = descriptorFor(collection);
  const NodeDescriptor* descriptor = nullptr;
  if (schema != nullptr) {
    descriptor = schema->nodeByKind("item");
  }
  if (descriptor == nullptr) {
    return matches;
  }
  std::string lowered = lowercase(needle);
  for (const std::string& nodeId : database_->nodesInCollection(collection)) {
    Result<Json> content = Status::NotFound;
    if (isIndexedItem(*database_->findNode(nodeId))) {
      content = readNode(nodeId);
    }
    if (!content.ok()) {
      continue;
    }
    std::vector<std::string> texts = searchableTexts(*descriptor, content.value());
    bool found = std::any_of(texts.begin(), texts.end(),
                             [&](const std::string& text) { return lowercase(text).find(lowered) != std::string::npos; });
    if (found) {
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
