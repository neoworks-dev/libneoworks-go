/*
 * libneoworks C ABI.
 *
 * Handle-based and exception-free: every function returns an nw_status, results
 * come back through out-parameters, and no C++ type crosses this boundary.
 * Structured data is exchanged as UTF-8 JSON in the shapes of the Neoworks
 * contract (binary values are base64url without padding). Buffers returned to
 * the caller are released with nw_buffer_free; buffers marked secret live in
 * locked, guard-paged memory and are zeroed when freed.
 *
 * Threads: handles are not synchronised. Calls on one nw_client, and on the
 * nw_sync and nw_blob_transfer objects made from it, must not overlap; separate
 * clients may be used from separate threads. nw_init may be called from any thread.
 */
#ifndef NEOWORKS_H
#define NEOWORKS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define NW_API __declspec(dllexport)
#else
#define NW_API __attribute__((visibility("default")))
#endif

typedef enum nw_status {
  NW_OK = 0,
  NW_ERR_INVALID_ARGUMENT = 1,
  NW_ERR_MALFORMED = 2,
  NW_ERR_AUTHENTICATION_FAILED = 3,
  NW_ERR_NOT_FOUND = 4,
  NW_ERR_CRYPTO = 5,
  NW_ERR_EXPIRED = 6,
  NW_ERR_UNSUPPORTED = 7,
  NW_ERR_INVALID_STATE = 8,
  NW_ERR_IO = 9,
  NW_ERR_CONFLICT = 10,
  NW_ERR_FORBIDDEN = 11,
  NW_ERR_RESYNC_REQUIRED = 12,
  NW_ERR_INTERNAL = 13,
  NW_ERR_INTEGRITY = 14
} nw_status;

typedef struct nw_buffer {
  uint8_t* data;
  size_t length;
  int secret;
} nw_buffer;

typedef struct nw_keystore nw_keystore;
typedef struct nw_install nw_install;
typedef struct nw_account nw_account;
typedef struct nw_client nw_client;
typedef struct nw_sync nw_sync;
typedef struct nw_blob_transfer nw_blob_transfer;
typedef struct nw_link_reader nw_link_reader;

NW_API int nw_init(void);
NW_API const char* nw_version(void);
NW_API const char* nw_status_name(int status);

/* The tag of a named facet (@neoworks.facet), as grants list them; "default" is tag 1. */
NW_API int nw_facet_tag(const char* facet_name, uint32_t* tag);

/* Fills a buffer from host code (callbacks use this to return data). */
NW_API int nw_buffer_set(nw_buffer* buffer, const uint8_t* data, size_t length);
NW_API void nw_buffer_free(nw_buffer* buffer);

/* ---- Keystore -------------------------------------------------------------
 * Wraps small secrets under a key held by the operating system. */

typedef struct nw_keystore_callbacks {
  void* user;
  const char* backend_name;
  /* Both return NW_OK and fill `out` via nw_buffer_set. */
  int (*wrap)(void* user, const uint8_t* secret, size_t secret_length, const uint8_t* label,
              size_t label_length, nw_buffer* out);
  int (*unwrap)(void* user, const uint8_t* wrapped, size_t wrapped_length, const uint8_t* label,
                size_t label_length, nw_buffer* out);
} nw_keystore_callbacks;

NW_API int nw_keystore_create_callbacks(const nw_keystore_callbacks* callbacks, nw_keystore** out);
/* Key lives only in this process; for tests and tools. */
NW_API int nw_keystore_create_ephemeral(nw_keystore** out);
/* Linux: TPM2, then libsecret. Returns NW_ERR_UNSUPPORTED where no backend exists,
 * which includes macOS, Windows, Android and distribution builds (NW_DISTRIBUTION):
 * there, hosts pass their OS keystore in through nw_keystore_create_callbacks. */
NW_API int nw_keystore_create_platform(const char* application_id, const char* data_directory,
                                       nw_keystore** out);
NW_API int nw_keystore_backend_name(nw_keystore* keystore, nw_buffer* name);
NW_API void nw_keystore_free(nw_keystore* keystore);

/* ---- Install ----------------------------------------------------------------
 * The per-installation identity: install id, X25519 + Ed25519 keypairs, store key. */

NW_API int nw_install_create(nw_install** out);
NW_API int nw_install_seal(const nw_install* install, nw_keystore* keystore, nw_buffer* persisted);
NW_API int nw_install_open(const uint8_t* persisted, size_t length, nw_keystore* keystore, nw_install** out);
/* {installId, installEncPub, installSignPub}: the authorization request parameters. */
NW_API int nw_install_describe(const nw_install* install, nw_buffer* json);
/* Host-keystore path (browsers): secrets are encEc(32) || signSec(64) || storeKey(32). */
NW_API int nw_install_export_secrets(const nw_install* install, nw_buffer* secrets);
NW_API int nw_install_import(const char* install_id, const uint8_t* enc_pub, const uint8_t* sign_pub,
                             const uint8_t* secrets, size_t secrets_length, nw_install** out);
NW_API void nw_install_free(nw_install* install);

/* ---- Account (vault holder: authenticator, account tools) ------------------- */

/* params_json: {"salt": base64url(16 bytes), "opsLimit": 3, "memLimit": 67108864} */
NW_API int nw_account_auth_key(const uint8_t* password, size_t password_length, const char* params_json,
                               nw_buffer* auth_key_base64url);
NW_API int nw_account_create(const char* user_id, const uint8_t* password, size_t password_length,
                             const char* params_json, nw_account** out, nw_buffer* bundle_json,
                             nw_buffer* recovery_entropy, nw_buffer* auth_key_base64url);
/* params_json may be NULL when the bundle carries pwhashSalt/pwhashOps/pwhashMem. */
NW_API int nw_account_unlock_password(const char* bundle_json, const uint8_t* password, size_t password_length,
                                      const char* params_json, nw_account** out);
NW_API int nw_account_unlock_recovery(const char* bundle_json, const uint8_t* recovery_entropy, size_t length,
                                      nw_account** out);
NW_API int nw_account_unlock_amk(const char* bundle_json, const uint8_t* amk, size_t length, nw_account** out);
NW_API int nw_account_export_amk(const nw_account* account, nw_buffer* amk);
/* seal(recipientPublicKey, AMK): the handover payload of contract section 9. */
NW_API int nw_account_seal_amk(const nw_account* account, const uint8_t* recipient_pub, size_t length,
                               nw_buffer* sealed);
NW_API int nw_account_identity(const nw_account* account, nw_buffer* json);
NW_API void nw_account_free(nw_account* account);

/* ---- Renewal (authenticator) ----------------------------------------------------
 * The authenticator holds an Ed25519 renewal key that can only extend existing delegation
 * certificates. The identity key certifies it once; a background job then renews on its own. */

/* A fresh renewal keypair. secret_key is secret. */
NW_API int nw_renewal_key_create(nw_buffer* public_key, nw_buffer* secret_key);
/* Signs a renewal certificate's bytes with the account's identity key (tlv("nw-renewal-v1", ...)). */
NW_API int nw_account_sign_renewal_certificate(const nw_account* account, const uint8_t* renewal_bytes,
                                               size_t renewal_length, nw_buffer* signature);
/* Extends `current_certificate` (the install's newest certificate bytes) and signs it with the renewal
 * key. Writes the POST /certificates/renew body {"certificate", "certificateSignature"}.
 * NW_ERR_EXPIRED: the renewal certificate is past renewal_expires_unix_seconds. */
NW_API int nw_renewal_renew_certificate(const uint8_t* renewal_secret, size_t secret_length,
                                        const char* renewal_cert_id, const uint8_t* current_certificate,
                                        size_t current_length, int64_t now_unix_seconds, int64_t lifetime_seconds,
                                        int64_t renewal_expires_unix_seconds, nw_buffer* body_json);

/* ---- Recovery words ----------------------------------------------------------
 * The 32 byte recovery entropy as 24 BIP39 English words (256 bits + 8 bit checksum). */

/* Writes the words separated by single spaces; secret. */
NW_API int nw_recovery_words_encode(const uint8_t* entropy, size_t length, nw_buffer* words);
/* Splits on spaces, commas and line breaks; case-insensitive. NW_ERR_MALFORMED: wrong count or an
 * unknown word; NW_ERR_AUTHENTICATION_FAILED: the checksum does not match. Writes the entropy; secret. */
NW_API int nw_recovery_words_decode(const char* words, nw_buffer* entropy);

/* ---- Contact codes -------------------------------------------------------------
 * The code a user hands out so apps can find their public keys (GET /contact-codes/{code}). */

/* Strips spaces and hyphens, uppercases, maps O/I/L to 0/1/1 and checks length, alphabet and the
 * check character. Writes the canonical 12 character code. NW_ERR_MALFORMED on any failure. */
NW_API int nw_contact_code_normalize(const char* contact_code, nw_buffer* canonical);

/* ---- Identity key history ------------------------------------------------------
 * A full rotation replaces the identity keys; the server keeps every version (GET
 * /users/{id}/identity-keys). Wherever an identity JSON is accepted below, it may carry that
 * response's `keys` array as `history`: a rotated identity that chains from the pinned one is
 * then a match and the pin follows it. */

/* identity_json: {userId, encPub, signPub, selfSig, version, history}. Checks every rotationSig
 * link from version 1 and that the history ends in the given identity. */
NW_API int nw_identity_verify_history(const char* identity_json);

/* ---- Client ------------------------------------------------------------------
 * Keys, encrypted local store, node operations and sync for one holder. */

typedef struct nw_storage_callbacks {
  void* user;
  int (*put)(void* user, const char* kind, const char* key, const uint8_t* value, size_t length);
  int (*remove)(void* user, const char* kind, const char* key);
  int (*clear)(void* user);
  /* Records loaded by the host before opening: repeated (kind, key, value) as
   * tlv("nw-records-v1", kind, key, value, kind, key, value, ...). May be NULL. */
  const uint8_t* snapshot;
  size_t snapshot_length;
} nw_storage_callbacks;

/* Storage: sqlite_path (native), else callbacks (browsers), else memory. */
NW_API int nw_client_open_install(const nw_install* install, const char* sqlite_path,
                                  const nw_storage_callbacks* callbacks, nw_client** out);
NW_API int nw_client_open_account(const nw_account* account, const char* sqlite_path,
                                  const nw_storage_callbacks* callbacks, nw_client** out);
NW_API void nw_client_free(nw_client* client);

/* Delegation intake: `neoworks_grant` from the token response and the owner's identity
 * ({userId, encPub, signPub, selfSig, version}). */
NW_API int nw_client_accept_grant(nw_client* client, const char* neoworks_grant_json,
                                  const char* owner_identity_json);

/* Verifies a delegation certificate (and, for a renewed one, its renewal certificate and origin)
 * against the pinned issuer's identity history and keeps it, so install-authored nodes verify.
 * NW_ERR_NOT_FOUND: the issuer is not pinned or a linked certificate is missing. */
NW_API int nw_client_store_certificate(nw_client* client, const uint8_t* certificate, size_t certificate_length,
                                       const uint8_t* signature, size_t signature_length);
NW_API int nw_client_store_renewal_certificate(nw_client* client, const uint8_t* renewal, size_t renewal_length,
                                               const uint8_t* signature, size_t signature_length);

/* Sets the OpenSchema descriptor (schema.descriptor.json) this client reads and writes the
 * collection "@scope/name" with, and its schema version "major.minor.patch" (the version in
 * openschema.yaml), which every node whose content the client encodes records, signed. Writes null
 * when the registry confirmed these bytes before, else {"descriptorHash", "method", "url", "isApi"}:
 * perform that request and pass the response to nw_client_complete_descriptor_check. Content of the
 * collection cannot be read or written before. NW_ERR_MALFORMED: not a valid descriptor;
 * NW_ERR_INVALID_ARGUMENT: not a valid version. */
NW_API int nw_client_register_descriptor(nw_client* client, const char* collection, const char* descriptor_json,
                                         const char* schema_version, nw_buffer* check_json);
/* NW_ERR_AUTHENTICATION_FAILED: the registry does not publish exactly these bytes for the
 * collection; NW_ERR_IO: any other failure, retry later. */
NW_API int nw_client_complete_descriptor_check(nw_client* client, const char* collection, int http_status,
                                               const uint8_t* body, size_t body_length);
/* Why the last create, update, read of content or query failed: {"status", "path", "reason"}, e.g.
 * {"path": "Event.attendees[2].email", "reason": "is not a valid email"}; null after a success. */
NW_API int nw_client_last_content_error(nw_client* client, nw_buffer* json);

/* request: {"collection": "@scope/name", "table": "Model", "content": {...}} for a row, or
 * {"collection", "kind": "root"} for the collection's root, which only an account creates.
 * content is a JSON object of the table's model (contract amendment 7 JSON mapping). A reference
 * is the id of a live row this client can read, of the table the field names; the core keeps that
 * row's key beside the id in the encrypted content and lists the row, unencrypted, in the new
 * row's links, so whoever reads the new row reads the referenced one. The @belongsTo field names
 * the row the new one belongs to: its key is wrapped under that row's key. Without it the row
 * sits under this client's root of the collection. A File value in it, {"objectId", "name",
 * "mediaType", "size", "variants"}, names the storage objects of the file and its variants; the
 * core lists them on the row, with their chunk counts, gives each new file a random key that it
 * keeps inside the encrypted content, and the host uploads the objects with nw_blob_upload_begin.
 * A File value or a reference never carries a key to or from the host; one that does is refused.
 * The row names its table in plain, next to its collection.
 * Writes the new row id. NW_ERR_INVALID_ARGUMENT: the content does not fit the table, or an
 * object id is used by more than one file of the row, see nw_client_last_content_error.
 * NW_ERR_NOT_FOUND: a referenced row is not readable here, or there is no root to put it under. */
NW_API int nw_client_create_node(nw_client* client, const char* request_json, nw_buffer* node_id);
/* request: {"nodeId": id, "changes": {...}}. A field in changes replaces the stored value, null
 * clears it, and fields not given keep their value. The row's file list and links follow its File
 * values and references. A File value with an object id the row holds keeps that file's key; any
 * other gets a new one. Giving the @belongsTo field another row moves the row below it: the row
 * keeps its key, content, files and links, the key is wrapped under the new parent's key, and the
 * rows below it are not written. The new parent must be a live row of the same owner and
 * collection, and this client needs write on the row, its old parent and the new parent. Clearing the field moves the row
 * to this client's root of the collection. NW_ERR_INVALID_ARGUMENT: a move
 * below the row itself or to a row of another owner. NW_ERR_NOT_FOUND: no such parent.
 * NW_ERR_FORBIDDEN: no write on the new parent. */
NW_API int nw_client_update_node(nw_client* client, const char* request_json);
/* Deletes the row, every row belonging to it, and every row linking to it through an
 * @onDelete("cascade") reference that this client may write. Writes the ids of the rows it
 * deleted as a JSON array, each row after the rows deleted with it and the requested row last;
 * a row that was already deleted is not listed. */
NW_API int nw_client_delete_node(nw_client* client, const char* node_id, nw_buffer* deleted_ids);
/* Writes the fields of the facets this client can open as one JSON object; a reference reads as the
 * id of its row. Roots read as {}. NW_ERR_NOT_FOUND: no such node or no facet this client can open. NW_ERR_INTEGRITY: the
 * node's file list does not match the File values in its content; the node is then reported as an
 * integrity failure by nw_sync_report. */
NW_API int nw_client_read_node(nw_client* client, const char* node_id, nw_buffer* json);
/* Reads an older version of a node this client holds. `version_json` is one entry of
 * GET /nodes/{id}/versions. Writes {"content": {...}, "verified": bool, "authorType", "authorId",
 * "seq", "deleted", "createdAt"}. NW_ERR_NOT_FOUND: no key for the node;
 * NW_ERR_AUTHENTICATION_FAILED: bad signature or ciphertext. */
NW_API int nw_client_read_version(nw_client* client, const char* version_json, nw_buffer* json);
/* Node metadata without key material or ciphertext: {"id", "parentId", "ownerId", "collection",
 * "kind", "deleted", "seq", "baseSeq", "authorType", "authorId", "createdAt", "updatedAt",
 * "dirty", "rejected", "role", "table": name|null, "files", "links"}. "table" is null for roots. */
NW_API int nw_client_get_node(nw_client* client, const char* node_id, nw_buffer* json);
/* parent_id and collection are optional filters (NULL = any). Returns a JSON array. */
NW_API int nw_client_list_nodes(nw_client* client, const char* parent_id, const char* collection,
                                nw_buffer* json);
NW_API int nw_client_effective_role(nw_client* client, const char* node_id, nw_buffer* role);
/* The rows of table in collection that match query_json, a Prisma-style filter:
 *   {"where": {...}, "orderBy": {"field": "asc"} | [{"field": "desc"}, ...], "take": n,
 *    "include": {"refField": true}}
 * where holds field filters (a bare value, or the operators equals, not, in, notIn, lt, lte, gt,
 * gte and, for text, contains, startsWith, endsWith with "mode": "insensitive") and AND, OR and NOT
 * lists or objects. A reference compares by the id of its row. Timestamps compare as instants.
 * A File field takes filters on its members, {"image": {"name": {"contains": "beach", "mode":
 * "insensitive"}, "size": {"gt": 1000}}} (name, mediaType, size), and orders by them,
 * "orderBy": {"image": {"name": "asc"}}. A list field takes some, every and none with a filter on
 * its elements, {"emails": {"some": {"contains": "anna@"}}}, and has for one plain element; the
 * members of one File element have to match together. An unset list has no elements.
 * The sorted indexes of the table's schema answer equality and range filters on their leading
 * fields and orderBy on them; any other query reads every row, with the same result.
 * Writes [{"id": id, "include"?: {"refField": id|null}}]: include names single references whose
 * row is read along, null when that row is deleted or not readable here. It reads the in-memory
 * index of field values and decrypts nothing. NW_ERR_INVALID_ARGUMENT: a field or table the
 * schema does not define, or an operator or value that does not fit the field's type, see
 * nw_client_last_content_error for the location. NW_ERR_INVALID_STATE: no confirmed descriptor for
 * the collection. NW_ERR_MALFORMED: not JSON. */
NW_API int nw_client_query(nw_client* client, const char* collection, const char* table, const char* query_json,
                           nw_buffer* json);
/* Wipes keys and all local data for this holder. */
NW_API int nw_client_wipe(nw_client* client);

/* ---- Identity pins and safety codes ----------------------------------------- */

/* state: 0 = new, 1 = matches the pin, 2 = changed since pinned. */
NW_API int nw_client_check_pin(nw_client* client, const char* identity_json, int* state);
NW_API int nw_client_pin_identity(nw_client* client, const char* identity_json);
/* After the user confirmed a changed key. Resets the verified flag. */
NW_API int nw_client_accept_identity_change(nw_client* client, const char* identity_json);
NW_API int nw_client_mark_verified(nw_client* client, const char* user_id);
NW_API int nw_client_safety_code(nw_client* client, const char* user_id, nw_buffer* digits);
NW_API int nw_client_list_pins(nw_client* client, nw_buffer* json);

/* ---- Sharing ------------------------------------------------------------------
 * Grants and revocations are queued and sent by the next sync. */

/* request: {"nodeId", "principalType": "user", "principalId", "role", "facets": [..]|null,
 *           "recipient": <identity json>}. Writes the signed AccessGrant JSON. One grant on the
 * row shares it, the rows belonging to it and, for reading, the rows they link to. */
NW_API int nw_client_share_node(nw_client* client, const char* request_json, nw_buffer* grant_json);
/* Removes the principal's grant; no key changes. The server stops sending the rows, and the
 * principal's next pull removes the rows it reached only through the grant. */
NW_API int nw_client_revoke_access(nw_client* client, const char* node_id, const char* principal_type,
                                   const char* principal_id);
NW_API int nw_client_list_grants(nw_client* client, const char* node_id, nw_buffer* json);

/* Link shares: the key travels in the URL fragment (`#k=`) and never reaches the server.
 * fragment_key is secret. link_request_json is the POST /links body. */
NW_API int nw_client_create_link_key(nw_client* client, const char* node_id, nw_buffer* fragment_key,
                                     nw_buffer* link_request_json);
NW_API int nw_client_record_link(nw_client* client, const char* node_id, const char* link_id);
NW_API int nw_client_list_links(nw_client* client, const char* node_id, nw_buffer* json);
/* Queues DELETE /links/{id}; no key changes. */
NW_API int nw_client_revoke_link(nw_client* client, const char* link_id);

/* Read-only view for visitors without an account; the only key is the URL fragment.
 * pull_json is the GET /links/{id}/pull response. */
NW_API int nw_link_open(const char* pull_json, const char* fragment_key, nw_link_reader** out);
NW_API int nw_link_list(nw_link_reader* reader, nw_buffer* json);
/* The descriptor link nodes of the collection are read with; no registry check for reading. */
NW_API int nw_link_set_descriptor(nw_link_reader* reader, const char* collection, const char* descriptor_json);
/* As nw_client_read_node. */
NW_API int nw_link_read_node(nw_link_reader* reader, const char* node_id, nw_buffer* json);
NW_API void nw_link_free(nw_link_reader* reader);

/* ---- Sync (sans-IO) ----------------------------------------------------------
 * The host performs the HTTP requests: nw_sync_next_request returns the next one
 * (method, url, isApi, contentType, body); feed the response to nw_sync_handle_response. */

NW_API int nw_sync_begin(nw_client* client, nw_sync** out);
/* *has_request = 0 once finished. meta: {"method","url","isApi","contentType"}. */
NW_API int nw_sync_next_request(nw_sync* sync, int* has_request, nw_buffer* meta_json, nw_buffer* body);
NW_API int nw_sync_handle_response(nw_sync* sync, int http_status, const uint8_t* body, size_t body_length);
NW_API int nw_sync_finished(const nw_sync* sync);
NW_API int nw_sync_report(const nw_sync* sync, nw_buffer* json);
NW_API void nw_sync_free(nw_sync* sync);

/* ---- Blobs -------------------------------------------------------------------- */

/* Sans-IO transfer of one file of a node, in 4 MiB chunks, through presigned URLs. object_id is the
 * "objectId" of a File value or of one of its variants; the node's file list must hold it, and its
 * size and chunk count come from there. The key comes from the File value in the fields this client
 * can open. NW_ERR_NOT_FOUND: the node does not list the object, or the field holding it cannot be
 * opened.
 * Upload: the host feeds plaintext chunks on request. Download: it receives plaintext. */
NW_API int nw_blob_upload_begin(nw_client* client, const char* node_id, const char* object_id,
                                nw_blob_transfer** out);
NW_API int nw_blob_download_begin(nw_client* client, const char* node_id, const char* object_id,
                                  nw_blob_transfer** out);
/* *state: 0 request ready, 1 need plaintext chunk `*chunk_index` (upload), 2 finished,
 * 3 plaintext chunk ready via nw_blob_take_chunk (download). */
/* Link visitors download without an account through POST /links/{id}/presign. */
NW_API int nw_blob_link_download_begin(nw_link_reader* reader, const char* link_id, const char* node_id,
                                       const char* object_id, nw_blob_transfer** out);
NW_API int nw_blob_next(nw_blob_transfer* transfer, int* state, uint32_t* chunk_index, nw_buffer* meta_json,
                        nw_buffer* body);
NW_API int nw_blob_provide_chunk(nw_blob_transfer* transfer, const uint8_t* plaintext, size_t length);
NW_API int nw_blob_handle_response(nw_blob_transfer* transfer, int http_status, const uint8_t* body,
                                   size_t body_length);
NW_API int nw_blob_take_chunk(nw_blob_transfer* transfer, uint32_t* chunk_index, nw_buffer* plaintext);
NW_API void nw_blob_free(nw_blob_transfer* transfer);

#if defined(NW_ENABLE_TEST_HOOKS)
/* Tests only: replaces all randomness with a fixed byte script. Absent from release builds. */
NW_API int nw_testing_set_random_script(const uint8_t* script, size_t length);
NW_API int nw_testing_restore_random(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NEOWORKS_H */
