package libneoworks

/*
#include <stdint.h>
#include <stdlib.h>
#include "neoworks.h"

int nwgoKeystoreWrap(void* user, const uint8_t* secret, size_t secret_length, const uint8_t* label,
                     size_t label_length, nw_buffer* out);
int nwgoKeystoreUnwrap(void* user, const uint8_t* wrapped, size_t wrapped_length, const uint8_t* label,
                       size_t label_length, nw_buffer* out);
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

// Keystore wraps small secrets under a key the operating system holds. The
// label binds a wrapped secret to its purpose; Unwrap must refuse another label.
type Keystore interface {
	Name() string
	Wrap(secret, label []byte) ([]byte, error)
	Unwrap(wrapped, label []byte) ([]byte, error)
}

// nativeKeystore is a Keystore handed to libneoworks through callbacks. The
// callbacks struct and the handle slot live in C memory, which C may keep.
type nativeKeystore struct {
	native    *C.nw_keystore
	handle    cgo.Handle
	slot      *C.uintptr_t
	callbacks *C.nw_keystore_callbacks
	name      *C.char
}

func openNativeKeystore(keystore Keystore) (*nativeKeystore, error) {
	opened := &nativeKeystore{handle: cgo.NewHandle(keystore), name: cString(keystore.Name())}
	opened.slot = (*C.uintptr_t)(C.malloc(C.size_t(unsafe.Sizeof(C.uintptr_t(0)))))
	*opened.slot = C.uintptr_t(opened.handle)
	opened.callbacks = (*C.nw_keystore_callbacks)(C.calloc(1, C.size_t(unsafe.Sizeof(C.nw_keystore_callbacks{}))))
	opened.callbacks.user = unsafe.Pointer(opened.slot)
	opened.callbacks.backend_name = opened.name
	opened.callbacks.wrap = (*[0]byte)(C.nwgoKeystoreWrap)
	opened.callbacks.unwrap = (*[0]byte)(C.nwgoKeystoreUnwrap)
	err := check(C.nw_keystore_create_callbacks(opened.callbacks, &opened.native))
	if err != nil {
		opened.free()
		return nil, err
	}
	return opened, nil
}

func (keystore *nativeKeystore) free() {
	if keystore.native != nil {
		C.nw_keystore_free(keystore.native)
	}
	C.free(unsafe.Pointer(keystore.callbacks))
	C.free(unsafe.Pointer(keystore.slot))
	freeString(keystore.name)
	keystore.handle.Delete()
}

func setBuffer(out *C.nw_buffer, data []byte) C.int {
	pointer, length := cBytes(data)
	return C.nw_buffer_set(out, pointer, length)
}

//export goKeystoreWrap
func goKeystoreWrap(handle C.uintptr_t, secret *C.uint8_t, secretLength C.size_t, label *C.uint8_t,
	labelLength C.size_t, out *C.nw_buffer,
) C.int {
	keystore := cgo.Handle(handle).Value().(Keystore)
	wrapped, err := keystore.Wrap(goBytes(secret, secretLength), goBytes(label, labelLength))
	if err != nil {
		return C.NW_ERR_CRYPTO
	}
	return setBuffer(out, wrapped)
}

//export goKeystoreUnwrap
func goKeystoreUnwrap(handle C.uintptr_t, wrapped *C.uint8_t, wrappedLength C.size_t, label *C.uint8_t,
	labelLength C.size_t, out *C.nw_buffer,
) C.int {
	keystore := cgo.Handle(handle).Value().(Keystore)
	secret, err := keystore.Unwrap(goBytes(wrapped, wrappedLength), goBytes(label, labelLength))
	if err != nil {
		return C.NW_ERR_AUTHENTICATION_FAILED
	}
	return setBuffer(out, secret)
}
