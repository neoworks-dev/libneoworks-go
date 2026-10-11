// Package native compiles libneoworks, libsodium and SQLite from csrc/, which
// packages/libneoworks/scripts/sync-go-module.sh in neoworks.dev fills. Each
// stub beside this file #includes one source, because cgo compiles only the
// files of a package's own directory. Importing it links them in.
package native

/*
#cgo CFLAGS: -w -O2 -fstack-protector-strong
#cgo CFLAGS: -DCONFIGURED -DSODIUM_STATIC -I${SRCDIR}/csrc/sodium/include -I${SRCDIR}/csrc/sodium/include/sodium
#cgo CFLAGS: -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=1
#cgo CXXFLAGS: -w -O2 -fstack-protector-strong -std=c++20 -DSODIUM_STATIC -DNW_HAVE_SQLITE=1
#cgo CXXFLAGS: -I${SRCDIR}/csrc/libneoworks/include -I${SRCDIR}/csrc/libneoworks/src
#cgo CXXFLAGS: -I${SRCDIR}/csrc/libneoworks/third_party -I${SRCDIR}/csrc/sodium/include -I${SRCDIR}/csrc/sqlite
#cgo linux LDFLAGS: -lm -lpthread -static-libstdc++ -static-libgcc
#cgo windows LDFLAGS: -ladvapi32 -lbcrypt
*/
import "C"
