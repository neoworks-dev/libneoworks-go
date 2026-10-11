#pragma once

#include "bytes.hpp"

namespace nw::testing {

// Replaces libsodium's random source with a fixed byte script. Every random
// request (nonces, key seeds, seal ephemerals) consumes bytes in call order and
// aborts when the script is exhausted. Compiled only with NW_ENABLE_TEST_HOOKS.
void setRandomScript(ByteView script);
void restoreSystemRandom();
size_t remainingScriptBytes();

}  // namespace nw::testing
