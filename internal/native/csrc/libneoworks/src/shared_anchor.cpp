// The shared library is the C ABI of neoworks_core; this file only gives the
// target a translation unit so the linker produces a library.
extern "C" const char* nw_version(void);

namespace {
[[maybe_unused]] const char* (*const keepAbiAlive)(void) = &nw_version;
}  // namespace
