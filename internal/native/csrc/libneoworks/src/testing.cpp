#include "testing.hpp"

#include <sodium.h>

#include <cstdlib>
#include <cstring>

namespace nw::testing {

namespace {

Bytes scriptedBytes;
size_t scriptPosition = 0;

const char* scriptedImplementationName() { return "nw-scripted"; }

void scriptedFill(void* destination, size_t length) {
  if (length > scriptedBytes.size() - scriptPosition) {
    std::abort();
  }
  std::memcpy(destination, scriptedBytes.data() + scriptPosition, length);
  scriptPosition += length;
}

uint32_t scriptedRandom32() {
  uint32_t value = 0;
  scriptedFill(&value, sizeof(value));
  return value;
}

void scriptedStir() {}

randombytes_implementation scriptedImplementation = {
    scriptedImplementationName, scriptedRandom32, scriptedStir, nullptr, scriptedFill, nullptr,
};

}  // namespace

void setRandomScript(ByteView script) {
  scriptedBytes.assign(script.begin(), script.end());
  scriptPosition = 0;
  randombytes_set_implementation(&scriptedImplementation);
}

void restoreSystemRandom() {
  scriptedBytes.clear();
  scriptPosition = 0;
  randombytes_set_implementation(&randombytes_internal_implementation);
}

size_t remainingScriptBytes() { return scriptedBytes.size() - scriptPosition; }

}  // namespace nw::testing
