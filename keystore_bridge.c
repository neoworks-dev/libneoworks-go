#include <stdint.h>

#include "neoworks.h"
#include "_cgo_export.h"

/* `user` points at the cgo.Handle of the Go Keystore. */
int nwgoKeystoreWrap(void* user, const uint8_t* secret, size_t secret_length, const uint8_t* label,
                     size_t label_length, nw_buffer* out) {
  return goKeystoreWrap(*(uintptr_t*)user, (uint8_t*)secret, secret_length, (uint8_t*)label, label_length, out);
}

int nwgoKeystoreUnwrap(void* user, const uint8_t* wrapped, size_t wrapped_length, const uint8_t* label,
                       size_t label_length, nw_buffer* out) {
  return goKeystoreUnwrap(*(uintptr_t*)user, (uint8_t*)wrapped, wrapped_length, (uint8_t*)label, label_length, out);
}
