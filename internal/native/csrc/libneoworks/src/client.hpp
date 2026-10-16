#pragma once

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "accesslog.hpp"
#include "account.hpp"
#include "database.hpp"
#include "descriptor.hpp"
#include "field_index.hpp"
#include "http.hpp"
#include "install.hpp"
#include "keyring.hpp"
#include "schema_codec.hpp"

namespace nw {

struct CreateNodeRequest {
  std::optional<std::string> parentId;
  std::string collection;
  std::string kind;
  // A JSON object of the collection's model for `kind`. Roots carry no content. The `File` values
  // in it name the storage objects the app uploads once the node is pushed; the core lists them
  // on the node.
  Json content = Json::object();
};

// An item under `parentId` that opens `targetId`, an item of the same collection, for
// whoever can open the parent: with at most `targetRole` ("read" or "write").
struct CreateShortcutRequest {
  std::string parentId;
  std::string targetId;
  std::string targetRole;
};

struct UpdateNodeRequest {
  std::string nodeId;
  // The top-level fields to change. A given field replaces the stored value, null clears it,
  // and fields not given keep their value.
  Json changes = Json::object();
};

enum class PinState { New, Match, Changed };

struct ShareRequest {
  std::string nodeId;
  std::string principalType;
  std::string principalId;
  std::string role;
  // Absent: the whole node and its subtree.
  std::optional<std::vector<uint32_t>> facets;
  Bytes principalEncPub;
};

struct RotationReport {
  std::vector<std::string> rotatedNodeIds;
};

struct LinkRecord {
  std::string nodeId;
  std::string linkId;
  std::string createdAt;
};

struct SafetyCode {
  std::string userId;
  std::string digits;
};

// An older version of a node, as served by GET /nodes/{id}/versions.
struct VersionRead {
  // The fields of the facets this client can open, as in readNode.
  Json content;
  // The write signature checked out against a known identity or delegation certificate.
  bool verified = false;
  std::string authorType;
  std::string authorId;
  uint64_t seq = 0;
  bool deleted = false;
  std::string createdAt;
};

// A registry request that must succeed before a descriptor is used.
struct DescriptorCheck {
  std::string descriptorHash;
  HttpRequest request;
};

// A holder of keys: either the account vault (user principal) or an app
// installation (install principal with a delegation certificate).
class Client {
 public:
  using Clock = std::function<int64_t()>;

  static std::unique_ptr<Client> forInstall(Install install, std::unique_ptr<LocalDatabase> database);
  static std::unique_ptr<Client> forAccount(Account account, std::unique_ptr<LocalDatabase> database);

  void setClock(Clock clock) { clock_ = std::move(clock); }
  std::string nowText() const;
  int64_t nowSeconds() const;

  const std::string& principalType() const { return signer_.authorType; }
  const std::string& principalId() const { return signer_.authorId; }
  ByteView encPub() const { return ByteView(encPub_); }
  ByteView signPub() const { return ByteView(signPub_); }
  LocalDatabase& database() { return *database_; }
  const LocalDatabase& database() const { return *database_; }
  Keyring& keyring() { return keyring_; }
  const std::optional<DelegationCertificate>& certificate() const { return certificate_; }
  PublicIdentity ownIdentity() const;

  // Delegation intake (install holders): verifies the certificate against the
  // owner's identity, checks every grant's signature, opens them and records keys.
  Status acceptGrantBundle(const Json& neoworksGrant, const PublicIdentity& ownerIdentity,
                           const std::vector<IdentityVersion>& ownerHistory = {});
  Status restoreKeysFromDatabase();

  // Sets the descriptor this client reads and writes `collection` with. Returns the registry
  // request that confirms it is a published version of the collection's schema, or nullopt
  // when that was confirmed before. Malformed: not a valid descriptor.
  Result<std::optional<DescriptorCheck>> registerDescriptor(const std::string& collection,
                                                           std::string_view descriptorText);
  // AuthenticationFailed: the registry does not publish exactly these bytes.
  Status completeDescriptorCheck(const std::string& collection, const HttpResponse& response);
  // The descriptor of `collection` once confirmed, nullptr before.
  const SchemaDescriptor* descriptorFor(const std::string& collection) const;
  // Why the last create, update, read of content or query was rejected.
  const CodecError& lastContentError() const { return lastContentError_; }

  Result<std::string> createNode(const CreateNodeRequest& request);
  Result<std::string> createShortcut(const CreateShortcutRequest& request);
  Status updateNode(const UpdateNodeRequest& request);
  Status deleteNode(const std::string& nodeId, bool recursive);
  // Re-signs the local pending edit on top of a newer server version (last-writer-wins).
  Status rebaseLocalNode(const std::string& nodeId, const Node& remote);
  // The fields of the facets this client can open. Roots and shortcuts read as {}.
  // NotFound: no such node or no facet can be opened.
  Result<Json> readNode(const std::string& nodeId);
  // Decrypts a version (the JSON object of GET /nodes/{id}/versions) of a node this client
  // knows, with the key of the version's epoch. NotFound: the node or that epoch's key is not
  // available here. AuthenticationFailed: the signature does not verify or the content does not
  // decrypt. A version whose author cannot be checked offline is unverified.
  Result<VersionRead> readVersion(const Json& version);
  Result<SymmetricKey> resolveNodeKey(const std::string& nodeId);
  // The key of the file that has the object `objectId` among its original and variants, read from
  // the File value in the fields of the node this client can open. NotFound: no such object in
  // those fields.
  Result<SymmetricKey> resolveFileKey(const std::string& nodeId, const std::string& objectId);
  NodeLookup nodeLookup() const;

  // Role this principal holds on the node: own grants on the node or an ancestor, and
  // through shortcuts to it, capped by certificate scopes. Empty string when none.
  std::string effectiveRole(const std::string& nodeId) const;

  // The ids of the items of `collection` matching `query`, a Prisma-style
  // `{ where, orderBy, take }` (see query.hpp), read from the in-memory index of the values of
  // every node this holder could open; nothing is decrypted. Only items are returned: containers
  // are indexed so that `where.parent.is` can filter on their fields. Fields are those of the
  // schema's item model. InvalidState: no confirmed descriptor for the collection.
  // InvalidArgument: the query does not fit the schema, see lastContentError.
  Result<std::vector<std::string>> query(const std::string& collection, const Json& query);
#if defined(NW_ENABLE_TEST_HOOKS)
  // How many times a node's content was decrypted for reading, by the index or by readNode.
  size_t contentDecryptions() const { return contentDecryptions_; }
#endif

  // Items whose @neoworks.timeRange interval overlaps [rangeStart, rangeEnd), in epoch
  // milliseconds.
  std::vector<std::string> queryRange(const std::string& collection, int64_t rangeStart, int64_t rangeEnd);
  // Items whose @neoworks.searchable fields contain `needle`, case-insensitively.
  std::vector<std::string> search(const std::string& collection, const std::string& needle);

  // Sharing: the owner, or an install holding `<collection>:share` for the owner. Grants and
  // revocations are queued as intents and signed into the access log when sent.
  Result<AccessGrant> shareNode(const ShareRequest& request);
  // Removes the principal's grant and gives the node a new key, so the removed principal cannot read
  // later writes. Records below it move to a new key at their own next write.
  Result<RotationReport> revokeAccess(const std::string& nodeId, const std::string& principalType,
                                      const std::string& principalId);
  // Link shares: the fragment key is base64url(u32be epoch || node key).
  Result<std::string> createLinkFragment(const std::string& nodeId);
  Status recordLink(const std::string& nodeId, const std::string& linkId);
  std::vector<LinkRecord> linksFor(const std::string& nodeId) const;
  Result<RotationReport> revokeLink(const std::string& linkId);

  // Identity pinning and safety codes.
  // `history` is the server's identity key history for the user (amendment 4). With it, a
  // rotated identity that chains from the pinned one is a Match instead of Changed, and the
  // pin follows it. Without it only the pinned keys verify signatures.
  PinState checkPin(const PublicIdentity& identity, const std::vector<IdentityVersion>& history = {}) const;
  Status pinIdentity(const PublicIdentity& identity, const std::vector<IdentityVersion>& history = {});
  Status acceptIdentityChange(const PublicIdentity& identity, const std::vector<IdentityVersion>& history = {});
  Status markIdentityVerified(const std::string& userId);
  Result<SafetyCode> safetyCode(const std::string& userId) const;

  // What must be fetched before a node can be verified, if anything.
  struct LookupNeed {
    // IdentityHistory only follows an Identity lookup within a sync session.
    enum class Kind { Identity, Certificate, RenewalCertificate, IdentityHistory };
    Kind kind = Kind::Identity;
    std::string id;
    // Fetch again although a pin exists, to detect a changed key.
    bool recheck = false;
  };
  std::optional<LookupNeed> lookupNeededFor(const Node& node) const;

  // A queued grant or revocation turned into a signed access log entry and the request that
  // appends it. The entry extends the locally verified head.
  struct SignedOperation {
    std::string method;
    std::string path;
    Json body;
    AccessLogEntry entry;
    std::optional<AccessGrant> grant;
  };
  Result<SignedOperation> signOutboxOperation(const Json& operation);
  Status recordAppended(const SignedOperation& operation);

  // Verifies and stores pulled entries (contiguity, signatures, authority). NotFound: a
  // lookup or the node is missing; ResyncRequired: a gap, fetch the full log; IntegrityFailure:
  // a fork, rollback or unauthorised entry, recorded for the user.
  Status appendVerifiedEntries(const std::string& nodeId, std::vector<AccessLogEntry> entries);
  std::optional<LookupNeed> lookupNeededForEntry(const AccessLogEntry& entry) const;
  // Accepts a pulled grant once its log entry is verified and matches it.
  Status acceptPulledGrant(const AccessGrant& grant);

  // Authenticity of a node received from the server: signature, author identity
  // and (for installs) delegation certificate. Call lookupNeededFor first.
  Status verifyRemoteNode(const Node& node) const;

  Status storeCertificate(const Bytes& certificateBytes, const Bytes& signature);
  Status storeRenewalCertificate(const Bytes& renewalBytes, const Bytes& signature);

 private:
  void restoreNewestCertificate();
  Result<DelegationCertificate> verifyRenewedFromStore(const DelegationCertificate& hint, const Bytes& certificateBytes,
                                                       const Bytes& signature) const;
  struct Signer {
    std::string authorType;
    std::string authorId;
    std::optional<std::string> certId;
    SecretBytes signSecret;
  };

  Client() = default;

  // The in-memory index of readable field values. A node is read into it when it is stored or
  // removed in the database, and again when keys, grants or descriptors that unlock it arrive.
  void attachIndex();
  void onNodeChanged(const std::string& nodeId);
  void onGrantChanged(const std::string& nodeId);
  void indexNode(const std::string& nodeId);
  void indexPendingNodes();
  void resetIndexOf(const std::string& collection);
  void evictNodesOutOfView(const std::string& collection);
  enum class OwnGrants { None, Revoked, Active };
  OwnGrants ownGrantsOn(const std::string& nodeId) const;
  bool holderLostView(const Node& node) const;
  Result<IndexedNode> indexEntryFor(const Node& node);
  Status attachToParent(Node& node, const SymmetricKey& nodeKey);
  // The node descriptor for content of `kind` in `collection`; records the reason on failure.
  Result<const NodeDescriptor*> nodeDescriptorFor(const std::string& collection, const std::string& kind);
  // The content as an app sees it: Files without their keys.
  Result<Json> readContent(const Node& node, const SymmetricKey* nodeKey);
  // The content as stored, Files with their keys.
  Result<Json> readStoredContent(const Node& node, const SymmetricKey* nodeKey);
  // The facet plaintexts of a node to create; roots have none.
  Result<FacetMap> encodeNewContent(const CreateNodeRequest& request);
  // `changes` with a key in every File value: the stored one when `stored` holds the File, else a
  // new one.
  Result<Json> withFileKeys(const NodeDescriptor& descriptor, const Json& changes, const FacetMap& stored);
  // The plain file list for facets about to be sealed into a node of `kind`; empty for nodes
  // without content.
  Result<std::vector<NodeFile>> filesOfContent(const std::string& collection, const std::string& kind,
                                               const FacetMap& plaintexts);
  Status signAndStore(Node& node);
  Status createOwnerGrant(const Node& root, const SymmetricKey& nodeKey);
  Status queueGrant(const AccessGrant& grant);
  std::string trustedOwnerOf(const Node& node) const;
  AuthorityContext authorityContextFor(const Node& node, const std::string& ownerId) const;
  int inheritedRankFor(const Node& node, const std::string& principalType, const std::string& principalId,
                       const std::string& ownerId) const;
  bool canManageAccess(const Node& node) const;
  Result<std::string> grantCertificateFor(const std::string& principalType, const std::string& principalId) const;
  std::string nextOutboxId();
  struct RotationStep;
  struct ContentChange {
    FacetMap plaintexts;
    std::vector<NodeFile> files;
  };
  Result<RotationStep> planNodeRotation(const Node& node, const std::string& removedType,
                                        const std::string& removedId);
  Status applyRotationStep(RotationStep& step, const SymmetricKey* newParentKey, uint32_t newParentEpoch);
  Status reissueGrant(const AccessGrant& old, const Bytes& encPub, uint32_t epoch, const SymmetricKey& nodeKey);
  // `change`, when set, replaces the content sealed under the new key.
  Status rotateNode(const std::string& nodeId, const std::string& removedType, const std::string& removedId,
                    const ContentChange* change, RotationReport& report);
  Status rekeyShortcuts(const std::string& targetId, const SymmetricKey& targetKey, uint32_t targetEpoch,
                        RotationReport& report);
  Status rekeyShortcut(const std::string& shortcutId, const SymmetricKey& targetKey, uint32_t targetEpoch);
  Status currentParentKey(const Node& node, SymmetricKey& parentKey, uint32_t& parentEpoch);
  // Stale: wrapped under an earlier key of its parent. Unknown: no parent, or one whose key this
  // holder lacks.
  enum class Wrapping { Current, Stale, Unknown };
  Wrapping wrappingOf(const Node& node);
  // From the topmost stale node among `nodeId` and its ancestors down to `nodeId`, whose keys a removed
  // principal may hold; empty when none is stale.
  std::vector<std::string> exposedChainOf(const std::string& nodeId);
  bool canRewrapShortcut(const Node& shortcut);
  // Whether a shortcut to the item that this holder may wrap again sits under a stale node, so a
  // removed principal may hold the item's key.
  bool isExposedThroughShortcuts(const Node& node);
  // Rotates the exposed ancestors of `nodeId` top down; true when `nodeId` itself is exposed.
  Result<bool> refreshAncestors(const std::string& nodeId, RotationReport& report);
  // Rotates `nodeId` and its ancestors where exposed, before something new is wrapped under it.
  Status refreshKeys(const std::string& nodeId, RotationReport& report);
  // Writes `change` to an exposed node under a new key; false when the node is not exposed.
  Result<bool> writeUnderNewKey(const std::string& nodeId, const ContentChange& change);
  Result<Bytes> encPubFor(const std::string& principalType, const std::string& principalId) const;
  // Writes and queues the grant described by `request`; the caller checked the right to share.
  Result<AccessGrant> grantNode(const ShareRequest& request);
  Status queueRevocation(const std::string& nodeId, const std::string& principalType, const std::string& principalId);
  int rankOnNode(const Node& node) const;
  int inheritedRank(const Node& node) const;
  // The best min(role on shortcut, targetRole) over live shortcuts to the node.
  int rankThroughShortcuts(const Node& node) const;
  int capByScopes(int rank, const Node& node) const;

  struct RegisteredDescriptor {
    std::shared_ptr<const SchemaDescriptor> schema;
    std::string descriptorHash;
    Bytes text;
    bool confirmed = false;
  };

  Signer signer_;
  Bytes encPub_;
  SecretBytes encSecret_;
  Bytes signPub_;
  std::optional<Account> account_;
  std::optional<DelegationCertificate> certificate_;
  std::unique_ptr<LocalDatabase> database_;
  Keyring keyring_;
  Clock clock_;
  int64_t lastOutboxStamp_ = 0;
  std::map<std::string, RegisteredDescriptor> descriptors_;
  CodecError lastContentError_;
  FieldIndex index_;
  // Nodes not in the index because they cannot be read yet.
  std::set<std::string> unindexedNodeIds_;
#if defined(NW_ENABLE_TEST_HOOKS)
  size_t contentDecryptions_ = 0;
#endif
};

}  // namespace nw
