package libneoworks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKeystore seals with AES-GCM under a random key, the label as associated data.
type testKeystore struct {
	aead cipher.AEAD
}

func newTestKeystore(t *testing.T) *testKeystore {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return &testKeystore{aead: aead}
}

func (keystore *testKeystore) Name() string { return "test" }

func (keystore *testKeystore) Wrap(secret, label []byte) ([]byte, error) {
	nonce := make([]byte, keystore.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return keystore.aead.Seal(nonce, nonce, secret, label), nil
}

func (keystore *testKeystore) Unwrap(wrapped, label []byte) ([]byte, error) {
	size := keystore.aead.NonceSize()
	if len(wrapped) < size {
		return nil, errors.New("short")
	}
	secret, err := keystore.aead.Open(nil, wrapped[:size], wrapped[size:], label)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}
	return secret, nil
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	install, err := NewInstall()
	if err != nil {
		t.Fatal(err)
	}
	defer install.Close()
	client, err := OpenClient(install, filepath.Join(t.TempDir(), "neoworks.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func readDescriptor(t *testing.T) []byte {
	t.Helper()
	descriptor, err := os.ReadFile(filepath.Join("testdata", "calendar.descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func TestInstallSealsAndOpensUnderTheKeystore(t *testing.T) {
	keystore := newTestKeystore(t)
	install, err := NewInstall()
	if err != nil {
		t.Fatal(err)
	}
	defer install.Close()
	created, err := install.Describe()
	if err != nil || created.InstallID == "" || created.InstallEncPub == "" || created.InstallSignPub == "" {
		t.Fatalf("describe: %+v %v", created, err)
	}
	sealed, err := install.Seal(keystore)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := OpenInstall(sealed, keystore)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	reopened, err := opened.Describe()
	if err != nil || reopened != created {
		t.Fatalf("reopened install %+v %v, want %+v", reopened, err, created)
	}

	if _, err := OpenInstall(sealed, newTestKeystore(t)); err == nil {
		t.Fatal("another keystore must not open the install")
	}
}

func TestDescriptorCheckAcceptsOnlyThePublishedBytes(t *testing.T) {
	client := newTestClient(t)
	descriptor := readDescriptor(t)
	request, err := client.RegisterDescriptor("@neoworks/calendar", descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if request == nil || request.Method != "GET" || !strings.HasPrefix(request.URL, "/api/v1/schemas/neoworks/calendar/descriptors/") {
		t.Fatalf("descriptor check request: %+v", request)
	}

	otherBytes := append(append([]byte{}, descriptor...), '\n')
	err = client.CompleteDescriptorCheck("@neoworks/calendar", 200, otherBytes)
	if !errors.Is(err, StatusAuthenticationFailed) {
		t.Fatalf("other bytes: got %v, want %v", err, StatusAuthenticationFailed)
	}
	if _, err := client.RegisterDescriptor("@neoworks/calendar", descriptor); err != nil {
		t.Fatal(err)
	}
	if err := client.CompleteDescriptorCheck("@neoworks/calendar", 200, descriptor); err != nil {
		t.Fatalf("published bytes: %v", err)
	}
}

func TestNodeOperationsNeedAGrant(t *testing.T) {
	client := newTestClient(t)
	nodes, err := client.ListNodes("", "@neoworks/calendar")
	if err != nil || len(nodes) != 0 {
		t.Fatalf("a fresh store lists %v %v", nodes, err)
	}
	if _, err := client.ReadNode("00000000-0000-0000-0000-000000000000"); !errors.Is(err, StatusNotFound) {
		t.Fatalf("reading an unknown node: got %v, want %v", err, StatusNotFound)
	}
}

func TestQueryRejectsWhatTheSchemaDoesNotAllow(t *testing.T) {
	client := newTestClient(t)
	collection := "@neoworks/calendar"
	if _, err := client.Query(collection, Query{}); !errors.Is(err, StatusInvalidState) {
		t.Fatalf("before the descriptor is confirmed: got %v, want %v", err, StatusInvalidState)
	}
	descriptor := readDescriptor(t)
	if _, err := client.RegisterDescriptor(collection, descriptor); err != nil {
		t.Fatal(err)
	}
	if err := client.CompleteDescriptorCheck(collection, 200, descriptor); err != nil {
		t.Fatal(err)
	}

	take := 5
	ids, err := client.Query(collection, Query{
		Where: map[string]any{
			"title":  map[string]any{"contains": "standup", "mode": "insensitive"},
			"parent": map[string]any{"is": map[string]any{"name": "Work"}},
			"OR":     []any{map[string]any{"description": nil}, map[string]any{"start": map[string]any{"gte": "2026-10-01T00:00:00Z"}}},
		},
		OrderBy: []map[string]string{{"start": "asc"}, {"title": "desc"}},
		Take:    &take,
	})
	if err != nil || len(ids) != 0 {
		t.Fatalf("a fresh store matches %v %v", ids, err)
	}

	_, err = client.Query(collection, Query{Where: map[string]any{"colour": "blue"}})
	var contentError *ContentError
	if !errors.As(err, &contentError) || !errors.Is(err, StatusInvalidArgument) || contentError.Path != "where.colour" {
		t.Fatalf("unknown field: got %v", err)
	}
	_, err = client.Query(collection, Query{Where: map[string]any{"start": map[string]any{"contains": "2026"}}})
	if !errors.As(err, &contentError) || contentError.Path != "where.start.contains" {
		t.Fatalf("operator that does not fit: got %v", err)
	}
	negative := -1
	if _, err := client.Query(collection, Query{Take: &negative}); !errors.Is(err, StatusInvalidArgument) {
		t.Fatalf("negative take: got %v", err)
	}
}

type recordingTransport struct {
	requests []Request
	status   int
}

func (transport *recordingTransport) Do(_ context.Context, request Request) (Response, error) {
	transport.requests = append(transport.requests, request)
	return Response{Status: transport.status}, nil
}

func TestSyncPerformsItsRequestsThroughTheTransport(t *testing.T) {
	client := newTestClient(t)
	transport := &recordingTransport{status: 401}
	report, err := client.Sync(context.Background(), transport)
	if err != nil {
		t.Fatal(err)
	}
	if len(transport.requests) == 0 {
		t.Fatal("sync made no request")
	}
	for _, request := range transport.requests {
		if !request.IsAPI || !strings.HasPrefix(request.URL, "/api/v1/") {
			t.Errorf("unexpected request %+v", request)
		}
	}
	if report.Failure == "" {
		t.Errorf("a refused sync must report its failure, got %+v", report)
	}
}

func TestTransportErrorsEndTheSync(t *testing.T) {
	client := newTestClient(t)
	_, err := client.Sync(context.Background(), failingTransport{})
	if !errors.Is(err, errOffline) {
		t.Fatalf("got %v, want %v", err, errOffline)
	}
	if _, err := client.ListNodes("", ""); err != nil {
		t.Fatalf("the client must stay usable after a failed sync: %v", err)
	}
}

var errOffline = errors.New("offline")

type failingTransport struct{}

func (failingTransport) Do(context.Context, Request) (Response, error) {
	return Response{}, errOffline
}
