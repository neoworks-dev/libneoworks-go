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
#include "query.hpp"
#include "schema_codec.hpp"

namespace nw {

struct CreateNodeRequest {
  std::string collection;
  // "root" for the collection's root, which only an account creates and which carries no
  // content, or "row".
  std::string kind = "row";
  // The row's table, by model name.
  std::string table;
  // A JSON object of the table's model. A reference is the id of a row; the core keeps that row's
  // key beside it and lists the row on the new one. The @belongsTo field names the row this one
  // belongs to; without it the row sits under this holder's root of the collection. The `File`
  // values name the storage objects the app uploads once the row is pushed; the core lists them
  // on the row.
  Json content = Json::object();
};

struct UpdateNodeRequest {
  std::string nodeId;
  // The top-level fields to change. A given field replaces the stored value, null clears it,
  // and fields not given keep their value.
  Json changes = Json::object();
  // The schema version to write the row at, when it is above the one the row is at: a migrated
  // write. Then `changes` is the whole content of the row in that version's shape, encoded with
  // that version's descriptor; fields it leaves out are unset. Without it a row can only be changed
  // at the version this client registered.
  std::optional<std::string> schemaVersion;
};

// A row's content with the schema version that wrote it, nullopt for a row written before rows
// recorded one and for roots.
struct RowRead {
  std::optional<std::string> schemaVersion;
  Json content;
};

struct RowReference {
  std::string id;
  std::string schemaVersion;
};

enum class PinState { New, Match, Changed };

struct ShareRequest {
  std::string nodeId;
  std::string principalType;
  std::string principalId;
  std::string role;
  // Absent: the whole row, the rows belonging to it and the rows they link to.
  std::optional<std::vector<uint32_t>> facets;
  Bytes principalEncPub;
  // When the grant stops giving access; signed with the grant. See isFutureExpiry.
  std::optional<std::string> expiresAt;
  // The id of the grant this one is made from. A user passing their share of someone else's row on to
  // their own install gets it filled in from their grant, and the grant then ends with that one.
  std::optional<std::string> via;
};

struct LinkRecord {
  std::string nodeId;
  std::string linkId;
  std::string createdAt;
  std::optional<std::string> expiresAt;
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

CodecError contentError(Status status, std::string path, std::string reason);

// The registry request for a collection's schema and the hashes of its published versions' descriptors.
HttpRequest schemaRecordRequest(const std::string& collection);
// The registry request for the descriptor of `collection` with the hash `descriptorHash`.
HttpRequest descriptorRequest(const std::string& collection, const std::string& descriptorHash);

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

  // Sets the descriptor this client reads and writes `collection` with, and the schema version
  // ("major.minor.patch") every node whose content it encodes records. Returns the registry
  // request that confirms it is a published version of the collection's schema, or nullopt
  // when that was confirmed before. Malformed: not a valid descriptor. InvalidArgument: not a
  // valid version.
  Result<std::optional<DescriptorCheck>> registerDescriptor(const std::string& collection,
                                                           std::string_view descriptorText,
                                                           std::string_view schemaVersion);
  // AuthenticationFailed: the registry does not publish exactly these bytes.
  Status completeDescriptorCheck(const std::string& collection, const HttpResponse& response);
  // The descriptor of `collection` once confirmed, nullptr before.
  const SchemaDescriptor* descriptorFor(const std::string& collection) const;
  // The versions below the registered one that rows of the registered collections were written
  // at, whose descriptors are not held yet. A row is read with the descriptor of the version that
  // wrote it; fetch each from the registry (schemaRecordRequest, descriptorRequest) and hand it to
  // acceptPublishedDescriptor. A sync session does this.
  std::vector<DescriptorNeed> missingDescriptors();
  // The descriptor text of `collection` at `version`: the registered one, or a published one held
  // from a sync. NotFound: this client holds no descriptor of that version.
  Result<std::string> descriptorText(const std::string& collection, const std::string& version) const;
  // Keeps the descriptor of a published version once `text` is exactly the descriptor with the
  // hash the registry publishes for it, and reads the rows written at that version.
  // AuthenticationFailed: the hash differs. Malformed: not a valid descriptor.
  Status acceptPublishedDescriptor(const DescriptorNeed& need, const std::string& descriptorHash, const Bytes& text);
  // Why the last create, update, read of content or query was rejected.
  const CodecError& lastContentError() const { return lastContentError_; }

  Result<std::string> createNode(const CreateNodeRequest& request);
  // A given field replaces the stored value. Giving the @belongsTo field another row moves the
  // row below it: the row key, content, files and links stay, the key is wrapped under the new
  // parent's key, and rows below the moved row are not written. The new parent must be a live row
  // of the owner and collection of the row, and this holder needs write on the row, on its old
  // parent and on the new parent. Clearing the field moves the row to this holder's root of the collection.
  // InvalidArgument: a move below the row itself or to another owner. NotFound: no such parent.
  Status updateNode(const UpdateNodeRequest& request);
  // Deletes the row, the rows belonging to it, and the rows linking to it through an
  // @onDelete("cascade") reference that this holder may write. Returns the ids of the rows it
  // deleted, each row after the rows deleted with it and the requested row last; a row that was
  // already deleted is not listed.
  Result<std::vector<std::string>> deleteNode(const std::string& nodeId);
  // Re-signs the local pending edit on top of a newer server version (last-writer-wins).
  Status rebaseLocalNode(const std::string& nodeId, const Node& remote);
  // The fields of the facets this client can open; a reference reads as the id of its row. Roots
  // read as {}. NotFound: no such node or no facet can be opened.
  Result<Json> readNode(const std::string& nodeId);
  // As readNode, with the schema version that wrote the row. The content is in the shape of that
  // version. Unsupported: the row was written at a version above the registered one.
  // InvalidState: the descriptor of the row's version is not held yet, see missingDescriptors.
  Result<RowRead> readRow(const std::string& nodeId);
  // The live rows of `table` in `collection` written at a version below `version`, by id. Rows
  // without a recorded version are not listed.
  Result<std::vector<RowReference>> rowsBelow(const std::string& collection, const std::string& table,
                                              const std::string& version) const;
  // The live rows of `collection` that are readable here but out of the query index, because they
  // were written at an earlier version on another compatibility line than the registered one, in id
  // order. Their field ordinals do not mean what the registered descriptor says, so the index needs
  // their content migrated to the registered version: see indexMigrated.
  std::vector<RowReference> rowsAwaitingMigratedIndex(const std::string& collection) const;
  // Puts a row listed by rowsAwaitingMigratedIndex into the query index with `content`, the row's
  // content migrated to the registered version in the shape readNode returns it, without writing
  // the row. The entry lasts until the row changes, is rewritten or leaves this holder's reach; a
  // row that changed is listed again. InvalidState: the row is not awaiting an entry.
  // InvalidArgument: the content is not an object.
  Status indexMigrated(const std::string& nodeId, const Json& content);
  // The table of a row, by model name; nullopt for roots and rows this holder does not have.
  std::optional<std::string> tableOf(const std::string& nodeId) const;
  // Decrypts a version (the JSON object of GET /nodes/{id}/versions) of a node this client
  // knows, with the node key. NotFound: the node or its key is not
  // available here. AuthenticationFailed: the signature does not verify or the content does not
  // decrypt. A version whose author cannot be checked offline is unverified.
  Result<VersionRead> readVersion(const Json& version);
  Result<SymmetricKey> resolveNodeKey(const std::string& nodeId);
  // The key of the file that has the object `objectId` among its original and variants, read from
  // the File value in the fields of the node this client can open. NotFound: no such object in
  // those fields.
  Result<SymmetricKey> resolveFileKey(const std::string& nodeId, const std::string& objectId);
  NodeLookup nodeLookup() const;

  // Role this principal holds on the row: owned, granted on the row or a row it belongs to, and
  // read through a row linking to it, capped by certificate scopes. Empty string when none.
  std::string effectiveRole(const std::string& nodeId) const;

  // The rows of `table` in `collection` matching `query`, a Prisma-style
  // `{ where, orderBy, take, include }` (see query.hpp), read from the in-memory index of the
  // values of every row this holder could open; nothing is decrypted. InvalidState: no confirmed
  // descriptor for the collection. InvalidArgument: the query does not fit the table, see
  // lastContentError.
  Result<std::vector<QueryRow>> query(const std::string& collection, const std::string& table, const Json& query);
#if defined(NW_ENABLE_TEST_HOOKS)
  // How many times a node's content was decrypted for reading, by the index or by readNode.
  size_t contentDecryptions() const { return contentDecryptions_; }
#endif

  // Sharing: the owner, or an install holding `<collection>:share` for the owner. Grants and
  // revocations are queued as intents and signed into the access log when sent.
  Result<AccessGrant> shareNode(const ShareRequest& request);
  // Removes the principal's grant. No key changes: the server stops sending the rows, and the
  // principal's next pull removes those it reached only through the grant.
  Status revokeAccess(const std::string& nodeId, const std::string& principalType, const std::string& principalId);
  // Link shares: the fragment key is base64url(node key). `expiresAt` (see isFutureExpiry) is
  // checked here and goes into the POST /links body the host sends; the server enforces it.
  Result<std::string> createLinkFragment(const std::string& nodeId, const std::optional<std::string>& expiresAt);
  Status recordLink(const std::string& nodeId, const std::string& linkId, const std::optional<std::string>& expiresAt);
  std::vector<LinkRecord> linksFor(const std::string& nodeId) const;
  Status revokeLink(const std::string& linkId);

  // Removes the rows the server no longer serves to this holder: deleted below a deleted row,
  // behind a revoked grant, or no longer linked. Rows with a local edit stay.
  void removeRowsOutOfReach(const std::vector<std::string>& nodeIds);

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

  // The in-memory index of readable field values. A row is read into it when it is stored or
  // removed in the database, and again when keys, grants or descriptors that unlock it arrive.
  void attachIndex();
  void onNodeChanged(const std::string& nodeId);
  void indexNode(const std::string& nodeId);
  void indexDependentsOf(const std::string& nodeId);
  std::vector<std::string> dependentsOf(const std::string& nodeId) const;
  void indexPendingNodes();
  void resetIndexOf(const std::string& collection);
  Result<IndexedNode> indexEntryFor(const Node& node);
  // Lists a row of an earlier compatibility line as awaiting migrated content once it is readable.
  void awaitMigratedIndex(const Node& node);
  Status acceptPulledRevocation(const AccessGrant& grant);

  // The schema a row is read with: the registered one for a row written at its version, the
  // fetched one for a row written below it. Unsupported for a row written above it.
  Result<const SchemaDescriptor*> schemaOfRow(const Node& node);
  Result<const SchemaDescriptor*> schemaAtVersion(const std::string& collection, const std::string& version);
  Result<const SchemaDescriptor*> publishedSchema(const std::string& collection, const std::string& version);
  Result<const TableDescriptor*> tableIn(const SchemaDescriptor& schema, const std::string& collection,
                                         const std::string& table);
  // The table of a row in the schema of the version that wrote it.
  Result<const TableDescriptor*> tableOfRow(const Node& node);
  // Whether the row's field ordinals mean what the registered descriptor says: it was written at
  // that version or below it on the same compatibility line.
  bool sharesFieldsWithRegistered(const Node& node) const;
  // Whether the row was written below the registered version on an earlier compatibility line.
  bool isOnEarlierLine(const Node& node) const;
  std::set<std::string> versionsBelowRegistered(const std::string& collection) const;
  // How a change to a row is written: the stored content is read with `storedTable`, the version
  // that wrote the row, and the new content is encoded with `writeTable` of `writeVersion`.
  struct UpdatePlan {
    const TableDescriptor* storedTable = nullptr;
    const TableDescriptor* writeTable = nullptr;
    std::string writeVersion;
    // The row moves to a later version, so the request holds its whole content.
    bool migrates = false;
  };
  Result<UpdatePlan> planUpdate(const Node& node, const UpdateNodeRequest& request);
  Result<UpdatePlan> planMigration(const Node& node, const TableDescriptor& storedTable, const std::string& target);
  Result<FacetMap> updatedPlaintexts(const UpdatePlan& plan, const UpdateNodeRequest& request, const FacetMap& previous);

  // A row's content as stored, Files and references with their keys, and the table it names.
  struct StoredContent {
    const TableDescriptor* table = nullptr;
    Json content;
  };
  // The table `table` of `collection`; records the reason on failure.
  Result<const TableDescriptor*> tableDescriptorFor(const std::string& collection, const std::string& table);
  // The stored content of the facets this holder can open, or all facets with `nodeKey`.
  Result<StoredContent> readStoredContent(const Node& node, const SymmetricKey* nodeKey);
  // The content as an app sees it: Files without their keys and references as ids.
  Result<Json> readContent(const Node& node, const SymmetricKey* nodeKey);
  // `changes`, in the shape of `table`, with a key in every File value: the stored one when
  // `stored`, read with `storedTable`, holds the File, else a new one.
  Result<Json> withFileKeys(const TableDescriptor& table, const TableDescriptor& storedTable, const Json& changes,
                            const FacetMap& stored);
  // `changes` with the keys of the files and of the referenced rows in it.
  Result<Json> withKeys(const TableDescriptor& table, const TableDescriptor& storedTable, const Json& changes,
                        const FacetMap& stored);
  // The key of `rowId` for a reference to it from a new write: a live row this holder can read, of
  // the table `table` names.
  Result<SymmetricKey> referencedRowKey(const std::string& rowId, const std::string& table);
  // The key of `target` as a row linking to it carries it.
  Result<SymmetricKey> keyThroughLinks(const Node& target);
  // Sets the row's file list and links from the facets about to be sealed into it.
  Status describeContent(const TableDescriptor& table, const FacetMap& plaintexts, Node& node);
  // The row a new row of `table` with `content` is placed under: its @belongsTo row, or this
  // holder's root of the collection.
  Result<std::string> parentOfNewRow(const std::string& collection, const TableDescriptor& table, const Json& content);
  // The root of `collection` owned by the user this holder acts for.
  const Node* ownRootOf(const std::string& collection) const;
  std::string actingUserId() const;
  Result<std::string> createRoot(const CreateNodeRequest& request);
  Result<std::string> createRow(const CreateNodeRequest& request);
  struct DeletionPass {
    std::set<std::string> visited;
    std::vector<std::string> deletedIds;
  };
  Status deleteRow(const std::string& nodeId, DeletionPass& pass);
  Status deleteCascadingLinkers(const std::string& targetId, DeletionPass& pass);
  // Whether `linker` refers to `targetId` through a reference marked @onDelete("cascade").
  bool cascadesFrom(const Node& linker, const std::string& targetId);
  // Places `node` under the row `changes` gives for the @belongsTo field (this holder's root when
  // it is cleared), when that is not its parent yet, and wraps `nodeKey` under the new parent.
  Status moveToNewParent(const TableDescriptor& table, const Json& changes, const SymmetricKey& nodeKey, Node& node);
  Status checkMoveTarget(const Node& node, const std::string& newParentId);
  bool isSelfOrBelow(const Node& candidate, const std::string& ancestorId) const;
  Status signAndStore(Node& node);
  Status attachToParent(Node& node, const SymmetricKey& nodeKey);
  Status createOwnerGrant(const Node& root, const SymmetricKey& nodeKey);
  Status queueGrant(const AccessGrant& grant);
  std::string trustedOwnerOf(const Node& node) const;
  AuthorityContext authorityContextFor(const Node& node, const std::string& ownerId) const;
  int inheritedRankFor(const Node& node, const std::string& principalType, const std::string& principalId,
                       const std::string& ownerId) const;
  bool canManageAccess(const Node& node) const;
  Result<std::string> grantCertificateFor(const std::string& principalType, const std::string& principalId) const;
  std::string nextOutboxId();
  // Records `version` on a node whose content this client just encoded.
  static void stampSchemaVersion(Node& node, const std::string& version);
  const std::string& registeredVersion(const std::string& collection) const;
  Result<Bytes> encPubFor(const std::string& principalType, const std::string& principalId) const;
  // Writes and queues the grant described by `request`; the caller checked the right to share.
  Result<AccessGrant> grantNode(const ShareRequest& request);
  // The signer's own whole-row grant on the row, or on the nearest row above it that has one.
  std::optional<AccessGrant> ownWholeGrantOn(const std::string& nodeId) const;
  std::optional<AccessGrant> ownGrantReaching(const Node& node) const;
  // Fills in `via` and the expiry when a user passes their share of someone else's row to their install.
  Result<ShareRequest> withSourceGrant(const Node& node, ShareRequest request) const;
  Status queueRevocation(const std::string& nodeId, const std::string& principalType, const std::string& principalId);
  int rankOnNode(const Node& node) const;
  // The best of the row's own rank, its parent's, and read through a row linking to it.
  int rankOf(const Node& node, std::map<std::string, int>& ranks) const;
  int rankThroughLinks(const Node& node, std::map<std::string, int>& ranks) const;
  int capByScopes(int rank, const Node& node) const;

  struct RegisteredDescriptor {
    std::shared_ptr<const SchemaDescriptor> schema;
    std::string descriptorHash;
    Bytes text;
    std::string schemaVersion;
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
  // The descriptors of earlier published versions, by "<collection> <version>".
  std::map<std::string, std::shared_ptr<const SchemaDescriptor>> publishedSchemas_;
  CodecError lastContentError_;
  FieldIndex index_;
  // Nodes not in the index because they cannot be read yet.
  std::set<std::string> unindexedNodeIds_;
  // Readable rows of an earlier compatibility line, which wait for indexMigrated.
  std::set<std::string> awaitingMigratedIndexIds_;
  // Rows whose key is being looked up through the rows linking to them, so a cycle of links ends.
  std::set<std::string> rowsResolvingThroughLinks_;
#if defined(NW_ENABLE_TEST_HOOKS)
  size_t contentDecryptions_ = 0;
#endif
};

}  // namespace nw
