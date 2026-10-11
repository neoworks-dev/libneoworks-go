#pragma once

#include <string>
#include <variant>

#include "schema_codec.hpp"
#include "wire.hpp"

namespace nw::codec {

constexpr size_t kMaxMessageDepth = 100;

// Tracks the path of the value being processed and records the first failure.
class Context {
 public:
  Context(CodecError& error, std::string root) : error_(error), path_(std::move(root)) {}

  bool fail(Status status, std::string reason);
  bool enter();
  void leave() { --depth_; }
  std::string& path() { return path_; }

 private:
  CodecError& error_;
  std::string path_;
  size_t depth_ = 0;
};

// Appends a segment to the context path for its lifetime.
class PathSegment {
 public:
  PathSegment(Context& context, const std::string& segment);
  ~PathSegment();
  PathSegment(const PathSegment&) = delete;
  PathSegment& operator=(const PathSegment&) = delete;

 private:
  Context& context_;
  size_t previousLength_;
};

std::string fieldSegment(const std::string& name);
std::string indexSegment(size_t index);
std::string keySegment(const std::string& key);

wire::WireType wireTypeOf(const ValueShape& value);
wire::WireType wireTypeOfScalar(Scalar scalar);

// A value as the constraints see it.
using ConstrainedValue = std::variant<std::monostate, double, std::string, ByteView>;
bool checkConstraints(const ValueConstraints& constraints, const ConstrainedValue& value, Context& context,
                      Status status);

struct IntegerRange {
  bool isSigned;
  int64_t minimum;
  uint64_t maximum;
};
// Ranges of the integer scalars that travel as JSON numbers.
std::optional<IntegerRange> narrowIntegerRange(Scalar scalar);
bool isWideInteger(Scalar scalar);

}  // namespace nw::codec
