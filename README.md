# libneoworks-go

Go bindings for libneoworks, the Neoworks client core: the install identity,
the end-to-end encrypted local store, node operations and the sync loop.

```go
import libneoworks "github.com/neoworks-dev/libneoworks-go"
```

The C++ core, libsodium and SQLite compile from source with cgo, so `go build`
needs a C compiler and a C++20 compiler and nothing else: no system libraries,
no pkg-config. The first build takes about half a minute; Go caches it after
that. On Linux, libstdc++ is linked statically.

Linux is tested. macOS is built in CI. Windows does not build yet
(neoworks-dev/neoworks.dev#45).

## Where this comes from

This repository is generated from `packages/libneoworks` in neoworks.dev, where
it is the submodule `packages/libneoworks/bindings/go`. `internal/native/csrc`
and the stubs beside it are written by `scripts/sync-go-module.sh` there and are
never edited by hand; `internal/native/csrc/SOURCE` names the commit they came
from. The Go files are maintained here.

The binding links SQLite and libsodium in. A program that links its own copy of
either through cgo (for example `mattn/go-sqlite3`) gets duplicate symbols.

## License

Apache-2.0, see `LICENSE`. libsodium is under the ISC license
(`licenses/libsodium`), SQLite is in the public domain.
