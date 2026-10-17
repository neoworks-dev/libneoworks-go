#include "sync.hpp"

#include <algorithm>
#include <cctype>

#include "timeutil.hpp"

namespace nw {

namespace {

constexpr int kMaxPushRounds = 3;
constexpr int kMaxOutboxAttempts = 3;
constexpr size_t kPushBatchSize = 100;
constexpr size_t kPullPageSize = 200;

Status statusForHttp(int httpStatus) {
  if (httpStatus == 401 || httpStatus == 403) {
    return Status::Forbidden;
  }
  if (httpStatus == 404) {
    return Status::NotFound;
  }
  if (httpStatus == 409) {
    return Status::Conflict;
  }
  if (httpStatus == 410) {
    return Status::ResyncRequired;
  }
  return Status::IoFailure;
}

bool isSuccess(int httpStatus) { return httpStatus >= 200 && httpStatus < 300; }

std::string lookupKey(const Client::LookupNeed& need) {
  if (need.kind == Client::LookupNeed::Kind::Identity && need.recheck) {
    return "recheck:" + need.id;
  }
  if (need.kind == Client::LookupNeed::Kind::Identity) {
    return "identity:" + need.id;
  }
  if (need.kind == Client::LookupNeed::Kind::IdentityHistory) {
    return "history:" + need.id;
  }
  if (need.kind == Client::LookupNeed::Kind::RenewalCertificate) {
    return "renewal:" + need.id;
  }
  return "certificate:" + need.id;
}

std::string percentEncode(const std::string& text) {
  static const char* hexDigits = "0123456789ABCDEF";
  std::string encoded;
  for (unsigned char character : text) {
    bool unreserved = std::isalnum(character) || character == '-' || character == '_' || character == '.';
    if (unreserved) {
      encoded += static_cast<char>(character);
      continue;
    }
    encoded += '%';
    encoded += hexDigits[character >> 4];
    encoded += hexDigits[character & 0x0f];
  }
  return encoded;
}

HttpRequest jsonRequest(const std::string& method, const std::string& url, const Bytes& body) {
  HttpRequest request;
  request.method = method;
  request.url = url;
  request.contentType = "application/json";
  request.body = body;
  return request;
}

HttpRequest bodylessRequest(const std::string& method, const std::string& url) {
  HttpRequest request;
  request.method = method;
  request.url = url;
  return request;
}

}  // namespace

SyncSession::SyncSession(Client& client) : client_(client) { pullCursor_ = client.database().cursor(); }

std::optional<HttpRequest> SyncSession::nextRequest() {
  while (phase_ != Phase::Done && !currentRequest_.has_value()) {
    currentRequest_ = produceRequest();
  }
  return currentRequest_;
}

std::optional<HttpRequest> SyncSession::produceRequest() {
  if (phase_ == Phase::PushNodes) {
    return produceFrom(buildPushRequest());
  }
  if (phase_ == Phase::PushOutbox) {
    return produceFrom(buildOutboxRequest());
  }
  if (phase_ == Phase::Pull) {
    return producePullRequest();
  }
  resolveConflicts();
  advancePhase();
  return std::nullopt;
}

std::optional<HttpRequest> SyncSession::produceFrom(std::optional<HttpRequest> request) {
  if (!request.has_value()) {
    advancePhase();
  }
  return request;
}

void SyncSession::advancePhase() {
  if (phase_ == Phase::PushNodes) {
    phase_ = Phase::PushOutbox;
    return;
  }
  if (phase_ == Phase::PushOutbox) {
    phase_ = Phase::Pull;
    return;
  }
  if (phase_ == Phase::Pull) {
    phase_ = Phase::ResolveConflicts;
    return;
  }
  bool pendingEdits = !client_.database().dirtyNodeIds().empty();
  if (pendingEdits && pushRounds_ < kMaxPushRounds) {
    attemptedThisRound_.clear();
    pullDone_ = false;
    phase_ = Phase::PushNodes;
    return;
  }
  phase_ = Phase::Done;
}

void SyncSession::finishWithFailure(Status failure) {
  report_.failure = failure;
  currentRequest_.reset();
  phase_ = Phase::Done;
}

Status SyncSession::handleResponse(const HttpResponse& response) {
  currentRequest_.reset();
  Awaiting expected = awaiting_;
  awaiting_ = Awaiting::Nothing;
  Status outcome = Status::InvalidState;
  if (expected == Awaiting::PushResult) {
    outcome = handlePushResponse(response);
  } else if (expected == Awaiting::OutboxResult) {
    outcome = handleOutboxResponse(response);
  } else if (expected == Awaiting::PullPage) {
    outcome = handlePullResponse(response);
  } else if (expected == Awaiting::Identity) {
    outcome = handleIdentityResponse(response);
  } else if (expected == Awaiting::IdentityHistory) {
    outcome = handleIdentityHistoryResponse(response);
  } else if (expected == Awaiting::RenewalCertificate) {
    outcome = handleRenewalCertificateResponse(response);
  } else if (expected == Awaiting::Certificate) {
    outcome = handleCertificateResponse(response);
  } else if (expected == Awaiting::AccessLog) {
    outcome = handleAccessLogResponse(response);
  }
  if (outcome != Status::Ok) {
    finishWithFailure(outcome);
  }
  return outcome;
}

namespace {

size_t nodeDepth(const LocalDatabase& database, const Node* node) {
  size_t depth = 0;
  const Node* cursor = node;
  while (cursor != nullptr && cursor->parentId.has_value() && depth < 64) {
    cursor = database.findNode(*cursor->parentId);
    if (cursor == nullptr) {
      break;
    }
    ++depth;
  }
  return depth;
}

}  // namespace

bool SyncSession::collectDirtyBatch(std::vector<Node>& batch) {
  std::vector<std::pair<size_t, std::string>> ordered;
  for (const std::string& id : client_.database().dirtyNodeIds()) {
    if (attemptedThisRound_.count(id) > 0) {
      continue;
    }
    ordered.emplace_back(nodeDepth(client_.database(), client_.database().findNode(id)), id);
  }
  std::sort(ordered.begin(), ordered.end());
  inFlight_.clear();
  for (const auto& [depth, id] : ordered) {
    if (batch.size() >= kPushBatchSize) {
      break;
    }
    const LocalNode* local = client_.database().findLocal(id);
    batch.push_back(local->node);
    inFlight_.push_back(InFlightPush{id, local->revision});
    attemptedThisRound_.insert(id);
  }
  return !batch.empty();
}

std::optional<HttpRequest> SyncSession::buildPushRequest() {
  if (phase_ == Phase::PushNodes && !roundStarted_) {
    ++pushRounds_;
    roundStarted_ = true;
  }
  std::vector<Node> batch;
  if (!collectDirtyBatch(batch)) {
    roundStarted_ = false;
    return std::nullopt;
  }
  awaiting_ = Awaiting::PushResult;
  return jsonRequest("POST", "/api/v1/nodes/push", nw::buildPushRequest(batch));
}

void SyncSession::applyPushResult(const PushResult& result) {
  auto inFlight = std::find_if(inFlight_.begin(), inFlight_.end(),
                               [&](const InFlightPush& entry) { return entry.id == result.id; });
  if (inFlight == inFlight_.end()) {
    return;
  }
  if (result.outcome == PushResult::Outcome::Ok) {
    client_.database().markPushed(result.id, result.seq, inFlight->revision);
    ++report_.pushedNodes;
    return;
  }
  if (result.outcome == PushResult::Outcome::Forbidden) {
    client_.database().markRejected(result.id);
    report_.forbiddenNodeIds.push_back(result.id);
  }
  if (result.requiredSchemaVersion.has_value()) {
    report_.outdatedNodes.emplace_back(result.id, *result.requiredSchemaVersion);
  }
}

Status SyncSession::handlePushResponse(const HttpResponse& response) {
  if (!isSuccess(response.status)) {
    return statusForHttp(response.status);
  }
  Result<std::vector<PushResult>> results = parsePushResponse(response.body);
  if (!results.ok()) {
    return results.status();
  }
  for (const PushResult& result : results.value()) {
    applyPushResult(result);
  }
  return Status::Ok;
}

std::optional<HttpRequest> SyncSession::buildOutboxRequest() {
  if (!logFetchQueue_.empty()) {
    return buildLogFetchRequest();
  }
  for (const auto& [operationId, operation] : client_.database().outboxOperations()) {
    if (skippedOutbox_.count(operationId) > 0) {
      continue;
    }
    std::optional<HttpRequest> request = outboxRequestFor(operation);
    if (!request.has_value()) {
      client_.database().removeOutboxOperation(operationId);
      continue;
    }
    outboxOperationId_ = operationId;
    outboxOperationIsRemoval_ = readString(operation, "op").value_or("") == "link-revoke";
    awaiting_ = Awaiting::OutboxResult;
    return request;
  }
  return std::nullopt;
}

// Grants and revocations are signed into the access log here, on top of the verified head.
std::optional<HttpRequest> SyncSession::outboxRequestFor(const Json& operation) {
  pendingSigned_.reset();
  std::optional<std::string> kind = readString(operation, "op");
  std::optional<std::string> nodeId = readString(operation, "nodeId");
  if (!kind || !nodeId || !isLowercaseUuid(*nodeId)) {
    return std::nullopt;
  }
  if (*kind == "link-revoke") {
    std::optional<std::string> linkId = readString(operation, "linkId");
    if (!linkId) {
      return std::nullopt;
    }
    return bodylessRequest("DELETE", "/api/v1/links/" + percentEncode(*linkId));
  }
  Result<Client::SignedOperation> signedOperation = client_.signOutboxOperation(operation);
  if (!signedOperation.ok()) {
    return std::nullopt;
  }
  pendingSigned_ = signedOperation.take();
  return jsonRequest(pendingSigned_->method, pendingSigned_->path, bytesOf(dumpCompact(pendingSigned_->body)));
}

std::optional<HttpRequest> SyncSession::buildLogFetchRequest() {
  fetchingLogFor_ = logFetchQueue_.front();
  logFetchQueue_.pop_front();
  awaiting_ = Awaiting::AccessLog;
  return bodylessRequest("GET", "/api/v1/nodes/" + fetchingLogFor_ + "/access-log");
}

Status SyncSession::handleAccessLogResponse(const HttpResponse& response) {
  std::string nodeId = fetchingLogFor_;
  fetchingLogFor_.clear();
  if (!isSuccess(response.status)) {
    return Status::Ok;
  }
  Result<std::vector<AccessLogEntry>> entries = parseAccessLogResponse(response.body);
  if (!entries.ok()) {
    return Status::Ok;
  }
  noteChainOutcome(nodeId, client_.appendVerifiedEntries(nodeId, entries.take()), false);
  retryDeferredGrants();
  return Status::Ok;
}

// Records what happened when pulled entries were verified. A gap triggers one fetch of the full log.
void SyncSession::noteChainOutcome(const std::string& nodeId, Status outcome, bool mayFetch) {
  if (outcome == Status::IntegrityFailure) {
    report_.integrityFailures.push_back(nodeId);
    return;
  }
  if (outcome == Status::ResyncRequired && mayFetch && fetchedLogs_.insert(nodeId).second) {
    logFetchQueue_.push_back(nodeId);
    return;
  }
  if (outcome != Status::Ok) {
    ++report_.unverifiableNodes;
  }
}

Status SyncSession::handleOutboxResponse(const HttpResponse& response) {
  bool logHeadMoved = response.status == 409 && pendingSigned_.has_value();
  if (logHeadMoved && ++outboxAttempts_[outboxOperationId_] <= kMaxOutboxAttempts) {
    logFetchQueue_.push_back(pendingSigned_->entry.nodeId);
    return Status::Ok;
  }
  bool removalAlreadyApplied = response.status == 404 && outboxOperationIsRemoval_;
  if (isSuccess(response.status) || removalAlreadyApplied || response.status == 409) {
    if (pendingSigned_.has_value() && isSuccess(response.status)) {
      client_.recordAppended(*pendingSigned_);
    }
    client_.database().removeOutboxOperation(outboxOperationId_);
    ++report_.sharingOperationsSent;
    return Status::Ok;
  }
  if (response.status == 404) {
    skippedOutbox_.insert(outboxOperationId_);
    return Status::Ok;
  }
  if (response.status == 403) {
    client_.database().removeOutboxOperation(outboxOperationId_);
    return Status::Ok;
  }
  return statusForHttp(response.status);
}

std::optional<HttpRequest> SyncSession::producePullRequest() {
  if (!page_.has_value() && !logFetchQueue_.empty()) {
    return buildLogFetchRequest();
  }
  if (!page_.has_value()) {
    if (pullDone_) {
      advancePhase();
      return std::nullopt;
    }
    awaiting_ = Awaiting::PullPage;
    return buildPullRequest();
  }
  std::optional<Client::LookupNeed> need = nextLookupNeeded();
  if (need.has_value()) {
    return buildLookupRequest(*need);
  }
  applyPage();
  return std::nullopt;
}

std::optional<HttpRequest> SyncSession::buildPullRequest() {
  std::string url = "/api/v1/nodes/pull?limit=" + std::to_string(kPullPageSize);
  if (!pullCursor_.empty()) {
    url += "&cursor=" + percentEncode(pullCursor_);
  }
  return bodylessRequest("GET", url);
}

std::optional<HttpRequest> SyncSession::buildLookupRequest(const Client::LookupNeed& need) {
  pendingLookup_ = need;
  if (need.kind == Client::LookupNeed::Kind::Identity) {
    awaiting_ = Awaiting::Identity;
    return bodylessRequest("GET", "/api/v1/keys/identity?userId=" + percentEncode(need.id));
  }
  if (need.kind == Client::LookupNeed::Kind::IdentityHistory) {
    awaiting_ = Awaiting::IdentityHistory;
    return bodylessRequest("GET", "/api/v1/users/" + percentEncode(need.id) + "/identity-keys");
  }
  if (need.kind == Client::LookupNeed::Kind::RenewalCertificate) {
    awaiting_ = Awaiting::RenewalCertificate;
    return bodylessRequest("GET", "/api/v1/renewal-certificates/" + percentEncode(need.id));
  }
  awaiting_ = Awaiting::Certificate;
  return bodylessRequest("GET", "/api/v1/certificates/" + percentEncode(need.id));
}

bool SyncSession::lookupStillNeeded(const Client::LookupNeed& need) const {
  if (failedLookups_.count(lookupKey(need)) > 0) {
    return false;
  }
  if (need.kind == Client::LookupNeed::Kind::Identity && need.recheck) {
    return recheckedUsers_.count(need.id) == 0;
  }
  if (need.kind == Client::LookupNeed::Kind::Identity) {
    return client_.database().findPin(need.id) == nullptr;
  }
  if (need.kind == Client::LookupNeed::Kind::IdentityHistory) {
    return heldIdentities_.count(need.id) > 0;
  }
  if (need.kind == Client::LookupNeed::Kind::RenewalCertificate) {
    return client_.database().findRenewalCertificate(need.id) == nullptr;
  }
  return client_.database().findCertificate(need.id) == nullptr;
}

std::optional<Client::LookupNeed> SyncSession::recheckNeeded() {
  for (size_t index = 0; index < page_->nodes.size(); ++index) {
    const Node& node = page_->nodes[index];
    bool candidate = !pageVerified_[index] && node.authorType == "user" &&
                     client_.database().findPin(node.authorId) != nullptr && recheckedUsers_.count(node.authorId) == 0;
    if (!candidate) {
      continue;
    }
    Status verified = client_.verifyRemoteNode(node);
    pageVerified_[index] = verified == Status::Ok;
    if (verified == Status::AuthenticationFailed) {
      return Client::LookupNeed{Client::LookupNeed::Kind::Identity, node.authorId, true};
    }
  }
  return std::nullopt;
}

std::optional<Client::LookupNeed> SyncSession::nextLookupNeeded() {
  while (!extraLookups_.empty()) {
    Client::LookupNeed need = extraLookups_.front();
    extraLookups_.pop_front();
    if (lookupStillNeeded(need)) {
      return need;
    }
  }
  for (const Node& node : page_->nodes) {
    std::optional<Client::LookupNeed> need = client_.lookupNeededFor(node);
    if (need.has_value() && lookupStillNeeded(*need)) {
      return need;
    }
  }
  for (const AccessLogEntry& entry : page_->accessLog) {
    std::optional<Client::LookupNeed> need = client_.lookupNeededForEntry(entry);
    if (need.has_value() && lookupStillNeeded(*need)) {
      return need;
    }
  }
  return recheckNeeded();
}

Status SyncSession::handlePullResponse(const HttpResponse& response) {
  if (response.status == 410) {
    return beginFullResync();
  }
  if (!isSuccess(response.status)) {
    return statusForHttp(response.status);
  }
  Result<PullPage> page = parsePullResponse(response.body);
  if (!page.ok()) {
    return page.status();
  }
  page_ = page.take();
  pageVerified_.assign(page_->nodes.size(), false);
  return Status::Ok;
}

Status SyncSession::beginFullResync() {
  if (report_.fullResync) {
    return Status::ResyncRequired;
  }
  report_.fullResync = true;
  pullCursor_.clear();
  client_.database().setCursor("");
  seenDuringResync_.clear();
  return Status::Ok;
}

Status SyncSession::handleIdentityResponse(const HttpResponse& response) {
  Client::LookupNeed need = *pendingLookup_;
  pendingLookup_.reset();
  Result<PublicIdentity> identity = Status::NotFound;
  if (isSuccess(response.status)) {
    identity = parseIdentity(response.body);
  }
  if (!identity.ok() || identity.value().userId != need.id) {
    failedLookups_.insert(lookupKey(need));
    return Status::Ok;
  }
  if (need.recheck) {
    recheckedUsers_.insert(need.id);
  }
  heldIdentities_[need.id] = identity.take();
  extraLookups_.push_front(Client::LookupNeed{Client::LookupNeed::Kind::IdentityHistory, need.id, need.recheck});
  return Status::Ok;
}

// A server without a key history leaves the identity pinned on its own, as before.
Status SyncSession::handleIdentityHistoryResponse(const HttpResponse& response) {
  Client::LookupNeed need = *pendingLookup_;
  pendingLookup_.reset();
  PublicIdentity identity = std::move(heldIdentities_.at(need.id));
  heldIdentities_.erase(need.id);
  Client::LookupNeed identityNeed{Client::LookupNeed::Kind::Identity, need.id, need.recheck};
  std::string identityKey = lookupKey(identityNeed);
  std::vector<IdentityVersion> history;
  if (isSuccess(response.status)) {
    std::optional<Json> json =
        parseJson(std::string_view(reinterpret_cast<const char*>(response.body.data()), response.body.size()));
    Result<std::vector<IdentityVersion>> parsed = Status::Malformed;
    if (json.has_value()) {
      parsed = identityHistoryFromJson(*json);
    }
    if (!parsed.ok()) {
      failedLookups_.insert(identityKey);
      return Status::Ok;
    }
    history = parsed.take();
  }
  PinState state = client_.checkPin(identity, history);
  if (state == PinState::Changed) {
    failedLookups_.insert(identityKey);
    blockedUsers_.insert(need.id);
    report_.pinConflicts.push_back(PinConflict{need.id});
    return Status::Ok;
  }
  if (client_.pinIdentity(identity, history) != Status::Ok) {
    failedLookups_.insert(identityKey);
    return Status::Ok;
  }
  retryDeferredCertificates();
  return Status::Ok;
}

Result<PublicIdentity> SyncSession::parseIdentity(const Bytes& body) const {
  std::optional<Json> json = parseJson(std::string_view(reinterpret_cast<const char*>(body.data()), body.size()));
  if (!json.has_value()) {
    return Status::Malformed;
  }
  return publicIdentityFromJson(*json);
}

Status SyncSession::handleCertificateResponse(const HttpResponse& response) {
  Client::LookupNeed need = *pendingLookup_;
  pendingLookup_.reset();
  if (!isSuccess(response.status)) {
    failedLookups_.insert(lookupKey(need));
    return Status::Ok;
  }
  std::optional<Json> json =
      parseJson(std::string_view(reinterpret_cast<const char*>(response.body.data()), response.body.size()));
  std::optional<Bytes> certificate;
  std::optional<Bytes> signature;
  if (json.has_value()) {
    certificate = readBytes(*json, "certificate");
    signature = readBytes(*json, "certificateSignature");
  }
  if (!certificate || !signature) {
    failedLookups_.insert(lookupKey(need));
    return Status::Ok;
  }
  Status stored = client_.storeCertificate(*certificate, *signature);
  if (stored == Status::NotFound) {
    deferCertificate(need, *certificate, *signature);
    return Status::Ok;
  }
  if (stored != Status::Ok) {
    failedLookups_.insert(lookupKey(need));
    return Status::Ok;
  }
  retryDeferredCertificates();
  return Status::Ok;
}

Status SyncSession::handleRenewalCertificateResponse(const HttpResponse& response) {
  Client::LookupNeed need = *pendingLookup_;
  pendingLookup_.reset();
  std::optional<Json> json;
  if (isSuccess(response.status)) {
    json = parseJson(std::string_view(reinterpret_cast<const char*>(response.body.data()), response.body.size()));
  }
  std::optional<Bytes> renewal;
  std::optional<Bytes> signature;
  if (json.has_value()) {
    renewal = readBytes(*json, "renewalCertificate");
    signature = readBytes(*json, "renewalCertificateSignature");
  }
  if (!renewal || !signature) {
    failedLookups_.insert(lookupKey(need));
    return Status::Ok;
  }
  Status stored = client_.storeRenewalCertificate(*renewal, *signature);
  if (stored == Status::NotFound) {
    Result<RenewalCertificate> hint = parseTrustedRenewalCertificate(*renewal);
    bool identityFailed = hint.ok() && failedLookups_.count("identity:" + hint.value().userId) > 0;
    if (hint.ok() && !identityFailed) {
      extraLookups_.push_back(Client::LookupNeed{Client::LookupNeed::Kind::Identity, hint.value().userId});
      extraLookups_.push_back(need);
      return Status::Ok;
    }
  }
  if (stored != Status::Ok) {
    failedLookups_.insert(lookupKey(need));
    return Status::Ok;
  }
  retryDeferredCertificates();
  return Status::Ok;
}

void SyncSession::deferCertificate(const Client::LookupNeed& need, const Bytes& certificate, const Bytes& signature) {
  Result<DelegationCertificate> hint = parseTrustedCertificate(certificate);
  if (!hint.ok()) {
    failedLookups_.insert(lookupKey(need));
    return;
  }
  if (deferredCertificates_.count(need.id) > 0) {
    failedLookups_.insert(lookupKey(need));
    return;
  }
  deferredCertificates_[need.id] = std::make_pair(certificate, signature);
  extraLookups_.push_back(Client::LookupNeed{Client::LookupNeed::Kind::Identity, hint.value().userId});
  if (hint.value().renewalCertId.has_value()) {
    extraLookups_.push_back(Client::LookupNeed{Client::LookupNeed::Kind::RenewalCertificate, *hint.value().renewalCertId});
    extraLookups_.push_back(Client::LookupNeed{Client::LookupNeed::Kind::Certificate, *hint.value().originCertId});
  }
  extraLookups_.push_back(need);
}

void SyncSession::retryDeferredCertificates() {
  for (auto entry = deferredCertificates_.begin(); entry != deferredCertificates_.end();) {
    Status stored = client_.storeCertificate(entry->second.first, entry->second.second);
    if (stored == Status::NotFound) {
      ++entry;
      continue;
    }
    entry = deferredCertificates_.erase(entry);
  }
}

bool SyncSession::isBlockedAuthor(const Node& node) const {
  if (blockedUsers_.empty()) {
    return false;
  }
  if (node.authorType == "user") {
    return blockedUsers_.count(node.authorId) > 0;
  }
  const StoredCertificate* stored = nullptr;
  if (node.certId.has_value()) {
    stored = client_.database().findCertificate(*node.certId);
  }
  return stored != nullptr && blockedUsers_.count(stored->certificate.userId) > 0;
}

void SyncSession::applyNode(Node node, bool verified) {
  bool rejected = isBlockedAuthor(node) || (!verified && client_.verifyRemoteNode(node) != Status::Ok);
  if (rejected) {
    ++report_.unverifiableNodes;
    return;
  }
  const LocalNode* local = client_.database().findLocal(node.id);
  if (local != nullptr && local->node.seq > node.seq) {
    return;
  }
  if (local != nullptr && local->dirty) {
    remoteDuringLocalEdit_.insert_or_assign(node.id, std::move(node));
    return;
  }
  client_.database().putRemoteNode(std::move(node));
  ++report_.appliedNodes;
}

void SyncSession::applyGrant(const AccessGrant& grant) {
  Status accepted = client_.acceptPulledGrant(grant);
  if (accepted == Status::Ok) {
    ++report_.grantsApplied;
    return;
  }
  if (accepted == Status::NotFound) {
    deferredGrants_.push_back(grant);
    return;
  }
  report_.integrityFailures.push_back(grant.nodeId);
}

void SyncSession::retryDeferredGrants() {
  std::vector<AccessGrant> waiting;
  waiting.swap(deferredGrants_);
  for (const AccessGrant& grant : waiting) {
    applyGrant(grant);
  }
}

void SyncSession::applyAccessLog(const std::vector<AccessLogEntry>& entries) {
  std::map<std::string, std::vector<AccessLogEntry>> byNode;
  for (const AccessLogEntry& entry : entries) {
    byNode[entry.nodeId].push_back(entry);
  }
  std::vector<std::pair<size_t, std::string>> ordered;
  for (const auto& [nodeId, group] : byNode) {
    const Node* node = client_.database().findNode(nodeId);
    ordered.emplace_back(nodeDepth(client_.database(), node), nodeId);
  }
  std::sort(ordered.begin(), ordered.end());
  for (const auto& [depth, nodeId] : ordered) {
    noteChainOutcome(nodeId, client_.appendVerifiedEntries(nodeId, byNode[nodeId]), true);
  }
}

void SyncSession::applyPage() {
  PullPage page = std::move(*page_);
  page_.reset();
  report_.pulledNodes += page.nodes.size();
  report_.malformedEntries += page.malformedEntries;
  for (size_t index = 0; index < page.nodes.size(); ++index) {
    seenDuringResync_.insert(page.nodes[index].id);
    applyNode(std::move(page.nodes[index]), pageVerified_[index]);
  }
  applyAccessLog(page.accessLog);
  for (const AccessGrant& grant : page.grants) {
    applyGrant(grant);
  }
  bool cursorStalled = page.hasMore && page.cursor == pullCursor_;
  pullCursor_ = page.cursor;
  client_.database().setCursor(page.cursor);
  if (cursorStalled) {
    finishWithFailure(Status::Malformed);
    return;
  }
  if (page.hasMore) {
    return;
  }
  pullDone_ = true;
  if (report_.fullResync) {
    finishFullResync();
  }
  client_.removeRowsOutOfReach();
}

void SyncSession::finishFullResync() {
  for (const std::string& id : client_.database().allNodeIds()) {
    const LocalNode* local = client_.database().findLocal(id);
    if (local->dirty || seenDuringResync_.count(id) > 0) {
      continue;
    }
    client_.keyring().forgetNode(id);
    client_.database().removeNode(id);
  }
}

namespace {

bool localEditIsNewer(const Node& local, const Node& remote) {
  std::optional<int64_t> localTime = parseInstant(local.updatedAt);
  std::optional<int64_t> remoteTime = parseInstant(remote.updatedAt);
  if (!localTime || !remoteTime) {
    return false;
  }
  return *localTime > *remoteTime;
}

}  // namespace

void SyncSession::resolveConflicts() {
  for (auto& [nodeId, remote] : remoteDuringLocalEdit_) {
    const LocalNode* local = client_.database().findLocal(nodeId);
    if (local == nullptr || !local->dirty || remote.seq <= local->node.baseSeq) {
      continue;
    }
    if (localEditIsNewer(local->node, remote) && client_.rebaseLocalNode(nodeId, remote) == Status::Ok) {
      ++report_.rebasedNodes;
      continue;
    }
    client_.database().saveShadow(local->node);
    client_.database().putRemoteNode(remote);
    ++report_.lostLocalEdits;
  }
  remoteDuringLocalEdit_.clear();
}

}  // namespace nw
