#pragma once

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "accesslog.hpp"
#include "account.hpp"
#include "delegation.hpp"
#include "grant.hpp"
#include "identity_history.hpp"
#include "node.hpp"
#include "store.hpp"

namespace nw {

struct LocalNode {
  Node node;
  bool dirty = false;
  // Server rejected the last push (forbidden); kept for the app to surface.
  bool rejected = false;
  // Incremented on every local edit so a push response can tell if the node changed meanwhile.
  uint64_t revision = 0;
};

struct PinnedIdentity {
  // The newest identity this client trusts; grants are sealed to its encPub.
  PublicIdentity identity;
  bool userVerified = false;
  std::string pinnedAt;
  // The verified key history, oldest first. Empty when the server never served one: the
  // pinned identity is then the only key signatures are checked against.
  std::vector<IdentityVersion> history;

  // Keys a signature of this user may verify under, newest first.
  std::vector<IdentityVersion> verificationKeys() const;
  // The keys the pin is anchored on: version 1 when there is a history, safety codes derive from it.
  const Bytes& anchorSignPub() const;
  const Bytes& anchorEncPub() const;
};

struct LinkEntry {
  std::string nodeId;
  std::string linkId;
  std::string createdAt;
};

struct StoredCertificate {
  DelegationCertificate certificate;
  Bytes certificateBytes;
  Bytes signature;
};

struct StoredRenewalCertificate {
  RenewalCertificate renewal;
  Bytes renewalBytes;
  Bytes signature;
};

// In-memory index over an encrypted record store. Every mutation is written
// through; nothing is kept in the clear on disk.
class LocalDatabase {
 public:
  static Result<std::unique_ptr<LocalDatabase>> open(std::unique_ptr<RecordBackend> backend, SymmetricKey storeKey);

  // Called with the node or grant's node id after a node or grant was stored or removed, and for
  // every node a wipe removes. Not called for records read while opening the database.
  using ChangeObserver = std::function<void(const std::string& nodeId)>;
  void setNodeObserver(ChangeObserver observer) { nodeObserver_ = std::move(observer); }
  void setGrantObserver(ChangeObserver observer) { grantObserver_ = std::move(observer); }

  size_t corruptRecords() const { return corruptRecords_; }

  const LocalNode* findLocal(const std::string& nodeId) const;
  const Node* findNode(const std::string& nodeId) const;
  Status putNode(Node node, bool dirty);
  Status putRemoteNode(Node node);
  Status markPushed(const std::string& nodeId, uint64_t seq, uint64_t pushedRevision);
  Status markRejected(const std::string& nodeId);
  Status removeNode(const std::string& nodeId);
  std::vector<std::string> childrenOf(const std::string& parentId) const;
  std::vector<std::string> nodesInCollection(const std::string& collection) const;
  // Shortcuts whose targetId is `targetId`, deleted ones included.
  std::vector<std::string> shortcutsTo(const std::string& targetId) const;
  std::vector<std::string> dirtyNodeIds() const;
  std::vector<std::string> allNodeIds() const;

  Status putGrant(const AccessGrant& grant);
  std::vector<AccessGrant> grantsForNode(const std::string& nodeId) const;
  std::vector<AccessGrant> allGrants() const;

  // Verified access log chains and their last head. A chain that no longer extends the
  // stored head is an integrity failure, kept until the user acknowledges it.
  std::vector<AccessLogEntry> chainOf(const std::string& nodeId) const;
  std::optional<LogHead> headOf(const std::string& nodeId) const;
  Status appendChainEntries(const std::string& nodeId, const std::vector<AccessLogEntry>& entries);
  Status recordIntegrityFailure(const std::string& nodeId, const std::string& reason);
  std::map<std::string, std::string> integrityFailures() const { return integrityFailures_; }

  std::string cursor() const { return cursor_; }
  Status setCursor(const std::string& cursor);

  const PinnedIdentity* findPin(const std::string& userId) const;
  Status putPin(const PinnedIdentity& pin);
  std::vector<PinnedIdentity> allPins() const;

  const StoredCertificate* findCertificate(const std::string& certId) const;
  Status putCertificate(const StoredCertificate& stored);
  std::vector<StoredCertificate> allCertificates() const;
  const StoredRenewalCertificate* findRenewalCertificate(const std::string& renewalCertId) const;
  Status putRenewalCertificate(const StoredRenewalCertificate& stored);

  // Sharing operations waiting for the next sync (grant creation and revocation).
  Status putOutboxOperation(const std::string& operationId, const Json& operation);
  Status removeOutboxOperation(const std::string& operationId);
  std::vector<std::pair<std::string, Json>> outboxOperations() const;

  Status putLink(const LinkEntry& link);
  Status removeLink(const std::string& linkId);
  const LinkEntry* findLink(const std::string& linkId) const;
  std::vector<LinkEntry> linksForNode(const std::string& nodeId) const;

  // Descriptor hashes the registry confirmed as published versions of a collection's schema.
  bool isDescriptorAccepted(const std::string& collection, const std::string& descriptorHash) const;
  Status acceptDescriptor(const std::string& collection, const std::string& descriptorHash);

  Status saveShadow(const Node& losingVersion);
  std::vector<Node> shadowsOf(const std::string& nodeId) const;

  Status wipe();

 private:
  explicit LocalDatabase(std::unique_ptr<EncryptedRecordStore> store) : store_(std::move(store)) {}

  Status persistLocalNode(const LocalNode& local);
  void storeLocalNode(LocalNode local);
  void indexNode(const LocalNode& local);
  void unindexNode(const LocalNode& local);
  void notifyNodeChanged(const std::string& nodeId) const;
  void load(std::string_view kind, std::string_view key, const Bytes& plaintext);
  void loadNode(const Bytes& plaintext);
  void loadGrant(const Bytes& plaintext);
  void loadPin(const Bytes& plaintext);
  void loadCertificate(const Bytes& plaintext);
  void loadRenewalCertificate(const Bytes& plaintext);
  void loadShadow(const Bytes& plaintext);
  void loadOutbox(std::string_view key, const Bytes& plaintext);
  void loadLink(const Bytes& plaintext);
  void loadChain(const Bytes& plaintext);
  void loadIntegrity(std::string_view key, const Bytes& plaintext);

  std::unique_ptr<EncryptedRecordStore> store_;
  std::map<std::string, LocalNode> nodes_;
  // Node ids by parent id, by shortcut target id and by collection, and the dirty ones, kept in
  // step with nodes_ by indexNode and unindexNode.
  std::map<std::string, std::set<std::string>> childrenByParent_;
  std::map<std::string, std::set<std::string>> shortcutsByTarget_;
  std::map<std::string, std::set<std::string>> nodesByCollection_;
  std::set<std::string> dirtyNodeIds_;
  // By "<nodeId>/<principalType>/<principalId>", so a node's grants are one key range.
  std::map<std::string, AccessGrant> grants_;
  std::map<std::string, PinnedIdentity> pins_;
  std::map<std::string, StoredCertificate> certificates_;
  std::map<std::string, StoredRenewalCertificate> renewalCertificates_;
  std::map<std::string, Node> shadows_;
  std::map<std::string, Json> outbox_;
  std::map<std::string, LinkEntry> links_;
  std::map<std::string, std::vector<AccessLogEntry>> chains_;
  std::map<std::string, std::string> integrityFailures_;
  // "<collection> <descriptorHash>"
  std::set<std::string> acceptedDescriptors_;
  std::string cursor_;
  size_t corruptRecords_ = 0;
  ChangeObserver nodeObserver_;
  ChangeObserver grantObserver_;
};

}  // namespace nw
