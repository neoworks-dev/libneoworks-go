#pragma once

#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "client.hpp"
#include "http.hpp"
#include "syncwire.hpp"

namespace nw {

struct PinConflict {
  std::string userId;
};

struct SyncReport {
  size_t pushedNodes = 0;
  size_t pulledNodes = 0;
  size_t appliedNodes = 0;
  size_t rebasedNodes = 0;
  size_t lostLocalEdits = 0;
  size_t unverifiableNodes = 0;
  size_t malformedEntries = 0;
  // Nodes whose access log failed verification: a fork, rollback or unauthorised entry.
  std::vector<std::string> integrityFailures;
  size_t grantsApplied = 0;
  size_t sharingOperationsSent = 0;
  bool fullResync = false;
  std::vector<std::string> forbiddenNodeIds;
  std::vector<PinConflict> pinConflicts;
  Status failure = Status::Ok;
};

class SyncSession {
 public:
  explicit SyncSession(Client& client);

  // The next request to perform, or nullopt once the session finished. Returns the
  // same request until handleResponse is called.
  std::optional<HttpRequest> nextRequest();
  Status handleResponse(const HttpResponse& response);
  bool finished() const { return phase_ == Phase::Done; }
  const SyncReport& report() const { return report_; }

 private:
  enum class Phase { PushNodes, PushOutbox, Pull, ResolveConflicts, Done };
  enum class Awaiting { Nothing, PushResult, OutboxResult, PullPage, Identity, IdentityHistory, Certificate, RenewalCertificate, AccessLog };

  struct InFlightPush {
    std::string id;
    uint64_t revision = 0;
  };

  std::optional<HttpRequest> produceRequest();
  std::optional<HttpRequest> produceFrom(std::optional<HttpRequest> request);
  std::optional<HttpRequest> producePullRequest();
  std::optional<HttpRequest> buildPushRequest();
  std::optional<HttpRequest> buildOutboxRequest();
  std::optional<HttpRequest> outboxRequestFor(const Json& operation);
  std::optional<HttpRequest> buildLogFetchRequest();
  Status handleAccessLogResponse(const HttpResponse& response);
  void noteChainOutcome(const std::string& nodeId, Status outcome, bool mayFetch);
  void applyAccessLog(const std::vector<AccessLogEntry>& entries);
  void retryDeferredGrants();
  std::optional<HttpRequest> buildPullRequest();
  std::optional<HttpRequest> buildLookupRequest(const Client::LookupNeed& need);

  Status handlePushResponse(const HttpResponse& response);
  Status handleOutboxResponse(const HttpResponse& response);
  Status handlePullResponse(const HttpResponse& response);
  Status handleIdentityResponse(const HttpResponse& response);
  Status handleIdentityHistoryResponse(const HttpResponse& response);
  Status handleCertificateResponse(const HttpResponse& response);
  Status handleRenewalCertificateResponse(const HttpResponse& response);
  Result<PublicIdentity> parseIdentity(const Bytes& body) const;

  void finishWithFailure(Status failure);
  void advancePhase();
  bool collectDirtyBatch(std::vector<Node>& batch);
  void applyPushResult(const PushResult& result);
  bool lookupStillNeeded(const Client::LookupNeed& need) const;
  std::optional<Client::LookupNeed> recheckNeeded();
  std::optional<Client::LookupNeed> nextLookupNeeded();
  void deferCertificate(const Client::LookupNeed& need, const Bytes& certificate, const Bytes& signature);
  void retryDeferredCertificates();
  Status beginFullResync();
  void applyPage();
  void applyGrant(const AccessGrant& grant);
  void applyNode(Node node, bool verified);
  void finishFullResync();
  void resolveConflicts();
  bool isBlockedAuthor(const Node& node) const;

  Client& client_;
  Phase phase_ = Phase::PushNodes;
  Awaiting awaiting_ = Awaiting::Nothing;
  SyncReport report_;
  std::optional<HttpRequest> currentRequest_;

  int pushRounds_ = 0;
  bool roundStarted_ = false;
  std::vector<InFlightPush> inFlight_;
  std::set<std::string> attemptedThisRound_;
  std::string outboxOperationId_;
  bool outboxOperationIsRemoval_ = false;
  std::set<std::string> skippedOutbox_;
  std::optional<Client::SignedOperation> pendingSigned_;
  std::map<std::string, int> outboxAttempts_;
  std::deque<std::string> logFetchQueue_;
  std::string fetchingLogFor_;
  std::set<std::string> fetchedLogs_;
  std::vector<AccessGrant> deferredGrants_;

  std::optional<PullPage> page_;
  // Which of the page's nodes already passed their signature check, by position.
  std::vector<bool> pageVerified_;
  bool pullDone_ = false;
  std::string pullCursor_;
  std::optional<Client::LookupNeed> pendingLookup_;
  std::deque<Client::LookupNeed> extraLookups_;
  // Identities fetched and waiting for their history before they are pinned.
  std::map<std::string, PublicIdentity> heldIdentities_;
  std::set<std::string> failedLookups_;
  std::set<std::string> blockedUsers_;
  std::set<std::string> recheckedUsers_;
  std::map<std::string, std::pair<Bytes, Bytes>> deferredCertificates_;
  std::map<std::string, Node> remoteDuringLocalEdit_;
  std::set<std::string> seenDuringResync_;
};

}  // namespace nw
