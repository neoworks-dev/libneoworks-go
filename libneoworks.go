// Package libneoworks binds the libneoworks C ABI: the install identity, the
// encrypted local store, node operations and the sans-IO sync loop. The C++
// core, libsodium and SQLite compile from source with cgo, so building needs a
// C and C++20 compiler and nothing else.
//
// Handles are not synchronised in C; a Client serialises its calls itself.
package libneoworks

/*
#cgo CFLAGS: -I${SRCDIR}/internal/native/csrc/libneoworks/include
#include <stdlib.h>
#include "neoworks.h"
*/
import "C"

import (
	"sync"
	"unsafe"

	// Compiles and links the C and C++ sources the binding calls into.
	_ "github.com/neoworks-dev/libneoworks-go/internal/native"
)

// Status is a libneoworks status code other than NW_OK.
type Status int

// Statuses callers act on.
const (
	StatusInvalidArgument      Status = C.NW_ERR_INVALID_ARGUMENT
	StatusMalformed            Status = C.NW_ERR_MALFORMED
	StatusAuthenticationFailed Status = C.NW_ERR_AUTHENTICATION_FAILED
	StatusNotFound             Status = C.NW_ERR_NOT_FOUND
	StatusExpired              Status = C.NW_ERR_EXPIRED
	StatusUnsupported          Status = C.NW_ERR_UNSUPPORTED
	StatusInvalidState         Status = C.NW_ERR_INVALID_STATE
	StatusConflict             Status = C.NW_ERR_CONFLICT
	StatusForbidden            Status = C.NW_ERR_FORBIDDEN
	StatusResyncRequired       Status = C.NW_ERR_RESYNC_REQUIRED
)

func (status Status) Error() string {
	return "libneoworks: " + C.GoString(C.nw_status_name(C.int(status)))
}

func check(code C.int) error {
	if code == C.NW_OK {
		return nil
	}
	return Status(code)
}

var (
	initOnce  sync.Once
	initError error
)

// initialize runs nw_init once per process.
func initialize() error {
	initOnce.Do(func() {
		initError = check(C.nw_init())
	})
	return initError
}

// Version is the linked libneoworks version.
func Version() string {
	return C.GoString(C.nw_version())
}

// takeBuffer copies a buffer libneoworks filled and frees it.
func takeBuffer(buffer *C.nw_buffer) []byte {
	defer C.nw_buffer_free(buffer)
	if buffer.data == nil {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.length))
}

// goBytes copies length bytes from C memory.
func goBytes(data *C.uint8_t, length C.size_t) []byte {
	if data == nil || length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(data), C.int(length))
}

// cBytes returns a pointer to the bytes for the duration of a C call.
func cBytes(data []byte) (*C.uint8_t, C.size_t) {
	if len(data) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&data[0])), C.size_t(len(data))
}

// cString allocates a C copy of text; free it with C.free.
func cString(text string) *C.char {
	return C.CString(text)
}

func freeString(text *C.char) {
	C.free(unsafe.Pointer(text))
}
