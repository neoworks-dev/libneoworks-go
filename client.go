package libneoworks

/*
#include <stdlib.h>
#include "neoworks.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Client holds the keys of the nodes this install was granted, the encrypted
// local store in SQLite, and runs node operations and sync. It is safe for
// concurrent use: calls into C are serialised.
type Client struct {
	mutex  sync.Mutex
	native *C.nw_client
}

// NodeKind is a node's place in a collection's tree.
type NodeKind string

// Node kinds.
const (
	NodeKindRoot      NodeKind = "root"
	NodeKindContainer NodeKind = "container"
	NodeKindItem      NodeKind = "item"
)

// NewNode asks for a node under ParentID. Content is the model's fields by name.
type NewNode struct {
	ParentID   string         `json:"parentId"`
	Collection string         `json:"collection"`
	Kind       NodeKind       `json:"kind"`
	Content    map[string]any `json:"content"`
}

// NodeUpdate changes some fields of a node; a nil value clears the field and
// fields left out keep their value.
type NodeUpdate struct {
	NodeID  string         `json:"nodeId"`
	Changes map[string]any `json:"changes"`
}

// NodeFile is one stored file of a node as the server sees it: the object and
// what it takes, without a name. A node lists the original and every variant of
// each File in its content.
type NodeFile struct {
	ObjectID string `json:"objectId"`
	Chunks   uint32 `json:"chunks"`
	Size     uint64 `json:"size"`
}

// NodeSummary is a node as the local store lists it, without its content.
type NodeSummary struct {
	ID         string     `json:"id"`
	ParentID   *string    `json:"parentId"`
	OwnerID    string     `json:"ownerId"`
	Collection string     `json:"collection"`
	Kind       NodeKind   `json:"kind"`
	Deleted    bool       `json:"deleted"`
	Dirty      bool       `json:"dirty"`
	Rejected   bool       `json:"rejected"`
	Role       string     `json:"role"`
	CreatedAt  string     `json:"createdAt"`
	UpdatedAt  string     `json:"updatedAt"`
	Files      []NodeFile `json:"files"`
}

// ContentError says why content did not fit the collection's schema.
type ContentError struct {
	Status Status `json:"-"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func (contentError *ContentError) Error() string {
	return fmt.Sprintf("%s: %s: %s", contentError.Status.Error(), contentError.Path, contentError.Reason)
}

func (contentError *ContentError) Unwrap() error {
	return contentError.Status
}

// OpenClient opens the install's client over the SQLite store at sqlitePath.
func OpenClient(install *Install, sqlitePath string) (*Client, error) {
	if err := initialize(); err != nil {
		return nil, err
	}
	path := cString(sqlitePath)
	defer freeString(path)
	client := &Client{}
	if err := check(C.nw_client_open_install(install.native, path, nil, &client.native)); err != nil {
		return nil, err
	}
	return client, nil
}

// Close frees the client. It must not be used afterwards.
func (client *Client) Close() {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	C.nw_client_free(client.native)
	client.native = nil
}

// AcceptGrant takes in the neoworks_grant of a token response, signed by the
// owner whose public identity is given; it pins the owner on first use.
func (client *Client) AcceptGrant(grant, ownerIdentity json.RawMessage) error {
	grantText := cString(string(grant))
	defer freeString(grantText)
	identityText := cString(string(ownerIdentity))
	defer freeString(identityText)
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return check(C.nw_client_accept_grant(client.native, grantText, identityText))
}

// RegisterDescriptor sets the descriptor a collection is read and written
// with, and its schema version "major.minor.patch", which every node whose
// content the client encodes records. It returns the registry request that
// confirms the descriptor, or nil when the registry confirmed these bytes before.
func (client *Client) RegisterDescriptor(collection string, descriptor []byte, schemaVersion string) (*Request, error) {
	collectionText := cString(collection)
	defer freeString(collectionText)
	descriptorText := cString(string(descriptor))
	defer freeString(descriptorText)
	versionText := cString(schemaVersion)
	defer freeString(versionText)
	var buffer C.nw_buffer
	client.mutex.Lock()
	err := check(C.nw_client_register_descriptor(client.native, collectionText, descriptorText, versionText, &buffer))
	client.mutex.Unlock()
	if err != nil {
		return nil, err
	}
	var request *Request
	if err := json.Unmarshal(takeBuffer(&buffer), &request); err != nil {
		return nil, fmt.Errorf("descriptor check: %w", err)
	}
	return request, nil
}

// CompleteDescriptorCheck passes the registry's answer to RegisterDescriptor's
// request; StatusAuthenticationFailed means the registry publishes other bytes.
func (client *Client) CompleteDescriptorCheck(collection string, status int, body []byte) error {
	collectionText := cString(collection)
	defer freeString(collectionText)
	data, length := cBytes(body)
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return check(C.nw_client_complete_descriptor_check(client.native, collectionText, C.int(status), data, length))
}

// CreateNode creates a node and returns its ID.
func (client *Client) CreateNode(node NewNode) (string, error) {
	request, err := json.Marshal(node)
	if err != nil {
		return "", fmt.Errorf("new node: %w", err)
	}
	requestText := cString(string(request))
	defer freeString(requestText)
	var buffer C.nw_buffer
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if err := client.contentCall(C.nw_client_create_node(client.native, requestText, &buffer)); err != nil {
		return "", err
	}
	return string(takeBuffer(&buffer)), nil
}

// UpdateNode changes some fields of a node.
func (client *Client) UpdateNode(update NodeUpdate) error {
	request, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("node update: %w", err)
	}
	requestText := cString(string(request))
	defer freeString(requestText)
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return client.contentCall(C.nw_client_update_node(client.native, requestText))
}

// DeleteNode deletes a node, and with recursive its descendants.
func (client *Client) DeleteNode(nodeID string, recursive bool) error {
	idText := cString(nodeID)
	defer freeString(idText)
	recursiveFlag := C.int(0)
	if recursive {
		recursiveFlag = 1
	}
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return check(C.nw_client_delete_node(client.native, idText, recursiveFlag))
}

// ReadNode returns the fields of the node this client can open, as JSON.
func (client *Client) ReadNode(nodeID string) (json.RawMessage, error) {
	idText := cString(nodeID)
	defer freeString(idText)
	var buffer C.nw_buffer
	client.mutex.Lock()
	defer client.mutex.Unlock()
	if err := client.contentCall(C.nw_client_read_node(client.native, idText, &buffer)); err != nil {
		return nil, err
	}
	return takeBuffer(&buffer), nil
}

// ListNodes lists the nodes under parentID in collection; an empty argument
// leaves that filter out. Deleted nodes are listed with Deleted set.
func (client *Client) ListNodes(parentID, collection string) ([]NodeSummary, error) {
	var parentText, collectionText *C.char
	if parentID != "" {
		parentText = cString(parentID)
		defer freeString(parentText)
	}
	if collection != "" {
		collectionText = cString(collection)
		defer freeString(collectionText)
	}
	var buffer C.nw_buffer
	client.mutex.Lock()
	err := check(C.nw_client_list_nodes(client.native, parentText, collectionText, &buffer))
	client.mutex.Unlock()
	if err != nil {
		return nil, err
	}
	var nodes []NodeSummary
	if err := json.Unmarshal(takeBuffer(&buffer), &nodes); err != nil {
		return nil, fmt.Errorf("node list: %w", err)
	}
	return nodes, nil
}

// Query is a Prisma-style filter over the items of one collection. Where holds
// field filters (a bare value, or the operators equals, not, in, notIn, lt,
// lte, gt, gte and for text contains, startsWith, endsWith with "mode":
// "insensitive"), AND, OR and NOT, and "parent": a container id, operators on
// it, or {"is": {...}} with filters on the container's fields. OrderBy lists
// one field and direction ("asc" or "desc") per entry. Take limits the count.
// File fields cannot be filtered or ordered on.
type Query struct {
	Where   map[string]any      `json:"where,omitempty"`
	OrderBy []map[string]string `json:"orderBy,omitempty"`
	Take    *int                `json:"take,omitempty"`
}

// Query returns the IDs of the items in collection that match query, in
// OrderBy order. It reads the in-memory index of field values and decrypts
// nothing. A field the schema does not define, or an operator or value that
// does not fit the field's type, is a *ContentError with StatusInvalidArgument;
// StatusInvalidState means the collection's descriptor is not confirmed yet.
func (client *Client) Query(collection string, query Query) ([]string, error) {
	request, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	collectionText := cString(collection)
	defer freeString(collectionText)
	requestText := cString(string(request))
	defer freeString(requestText)
	var buffer C.nw_buffer
	client.mutex.Lock()
	err = client.contentCall(C.nw_client_query(client.native, collectionText, requestText, &buffer))
	client.mutex.Unlock()
	if err != nil {
		return nil, err
	}
	var ids []string
	if err := json.Unmarshal(takeBuffer(&buffer), &ids); err != nil {
		return nil, fmt.Errorf("query result: %w", err)
	}
	return ids, nil
}

// Wipe deletes everything the local store holds; the install keeps its keys.
func (client *Client) Wipe() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return check(C.nw_client_wipe(client.native))
}

// contentCall turns a failed content operation into a ContentError when
// libneoworks recorded why. The caller holds the mutex.
func (client *Client) contentCall(code C.int) error {
	err := check(code)
	var status Status
	if !errors.As(err, &status) {
		return err
	}
	var buffer C.nw_buffer
	if C.nw_client_last_content_error(client.native, &buffer) != C.NW_OK {
		return err
	}
	contentError := &ContentError{Status: status}
	if json.Unmarshal(takeBuffer(&buffer), contentError) != nil || contentError.Reason == "" {
		return err
	}
	return contentError
}
