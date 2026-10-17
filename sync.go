package libneoworks

/*
#include "neoworks.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
)

// Request is an HTTP request libneoworks asks the host to perform. URL is a
// path on the API when IsAPI is set, sent with the user's access token.
type Request struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	IsAPI       bool   `json:"isApi"`
	ContentType string `json:"contentType"`
	Body        []byte `json:"-"`
}

// Response is the answer to a Request.
type Response struct {
	Status int
	Body   []byte
}

// Transport performs the requests of the descriptor check and of sync.
type Transport interface {
	Do(ctx context.Context, request Request) (Response, error)
}

// SyncReport is what one sync run did.
type SyncReport struct {
	PushedNodes       int      `json:"pushedNodes"`
	PulledNodes       int      `json:"pulledNodes"`
	AppliedNodes      int      `json:"appliedNodes"`
	RebasedNodes      int      `json:"rebasedNodes"`
	LostLocalEdits    int      `json:"lostLocalEdits"`
	UnverifiableNodes int      `json:"unverifiableNodes"`
	GrantsApplied     int      `json:"grantsApplied"`
	FullResync        bool     `json:"fullResync"`
	ForbiddenNodeIDs  []string `json:"forbiddenNodeIds"`
	// OutdatedNodes are the forbidden rows the server refused because their owner
	// migrated past the schema version this client writes.
	OutdatedNodes []OutdatedNode `json:"outdatedNodes"`
	Failure       string         `json:"failure"`
	// FailureCode is zero when the run succeeded.
	FailureCode Status `json:"failureCode"`
}

// OutdatedNode is a row refused for an outdated schema, and the version to update to.
type OutdatedNode struct {
	NodeID          string `json:"nodeId"`
	RequiredVersion string `json:"requiredVersion"`
}

// Sync pushes local changes and pulls remote ones, performing the requests
// through transport. The client stays usable while a request is in flight.
// A transport error ends the run; a failure libneoworks hit is in the report.
func (client *Client) Sync(ctx context.Context, transport Transport) (SyncReport, error) {
	var report SyncReport
	var native *C.nw_sync
	client.mutex.Lock()
	err := check(C.nw_sync_begin(client.native, &native))
	client.mutex.Unlock()
	if err != nil {
		return report, err
	}
	defer client.freeSync(native)
	for {
		request, ok, err := client.nextSyncRequest(native)
		if err != nil {
			return report, err
		}
		if !ok {
			break
		}
		response, err := transport.Do(ctx, request)
		if err != nil {
			return report, fmt.Errorf("sync %s %s: %w", request.Method, request.URL, err)
		}
		client.handleSyncResponse(native, response)
	}
	return client.syncReport(native)
}

func (client *Client) nextSyncRequest(native *C.nw_sync) (Request, bool, error) {
	var request Request
	var hasRequest C.int
	var meta, body C.nw_buffer
	client.mutex.Lock()
	err := check(C.nw_sync_next_request(native, &hasRequest, &meta, &body))
	client.mutex.Unlock()
	metaJSON := takeBuffer(&meta)
	request.Body = takeBuffer(&body)
	if err != nil || hasRequest == 0 {
		return request, false, err
	}
	if err := json.Unmarshal(metaJSON, &request); err != nil {
		return request, false, fmt.Errorf("sync request: %w", err)
	}
	return request, true, nil
}

// handleSyncResponse ignores the status: a failure ends the run and is reported.
func (client *Client) handleSyncResponse(native *C.nw_sync, response Response) {
	data, length := cBytes(response.Body)
	client.mutex.Lock()
	defer client.mutex.Unlock()
	C.nw_sync_handle_response(native, C.int(response.Status), data, length)
}

func (client *Client) syncReport(native *C.nw_sync) (SyncReport, error) {
	var report SyncReport
	var buffer C.nw_buffer
	client.mutex.Lock()
	err := check(C.nw_sync_report(native, &buffer))
	client.mutex.Unlock()
	if err != nil {
		return report, err
	}
	if err := json.Unmarshal(takeBuffer(&buffer), &report); err != nil {
		return report, fmt.Errorf("sync report: %w", err)
	}
	return report, nil
}

func (client *Client) freeSync(native *C.nw_sync) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	C.nw_sync_free(native)
}
