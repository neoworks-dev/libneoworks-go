package libneoworks

/*
#include "neoworks.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
)

// Install is this installation's identity: install ID, encryption and signing
// keypairs and the local store key. It is sealed under the OS keystore between runs.
type Install struct {
	native *C.nw_install
}

// InstallDescription holds the install's public half, sent with the
// authorization request.
type InstallDescription struct {
	InstallID      string `json:"installId"`
	InstallEncPub  string `json:"installEncPub"`
	InstallSignPub string `json:"installSignPub"`
}

// NewInstall creates a fresh install identity.
func NewInstall() (*Install, error) {
	if err := initialize(); err != nil {
		return nil, err
	}
	install := &Install{}
	if err := check(C.nw_install_create(&install.native)); err != nil {
		return nil, err
	}
	return install, nil
}

// OpenInstall unseals an install that Seal wrote.
func OpenInstall(sealed []byte, keystore Keystore) (*Install, error) {
	if err := initialize(); err != nil {
		return nil, err
	}
	native, err := openNativeKeystore(keystore)
	if err != nil {
		return nil, err
	}
	defer native.free()
	install := &Install{}
	data, length := cBytes(sealed)
	if err := check(C.nw_install_open(data, length, native.native, &install.native)); err != nil {
		return nil, err
	}
	return install, nil
}

// Seal wraps the install's secrets under the keystore for OpenInstall.
func (install *Install) Seal(keystore Keystore) ([]byte, error) {
	native, err := openNativeKeystore(keystore)
	if err != nil {
		return nil, err
	}
	defer native.free()
	var sealed C.nw_buffer
	if err := check(C.nw_install_seal(install.native, native.native, &sealed)); err != nil {
		return nil, err
	}
	return takeBuffer(&sealed), nil
}

// Describe returns the install's ID and public keys.
func (install *Install) Describe() (InstallDescription, error) {
	var description InstallDescription
	var buffer C.nw_buffer
	if err := check(C.nw_install_describe(install.native, &buffer)); err != nil {
		return description, err
	}
	if err := json.Unmarshal(takeBuffer(&buffer), &description); err != nil {
		return description, fmt.Errorf("install description: %w", err)
	}
	return description, nil
}

// Close frees the install; a Client opened from it keeps working.
func (install *Install) Close() {
	C.nw_install_free(install.native)
	install.native = nil
}
