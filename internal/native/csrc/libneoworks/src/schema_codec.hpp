#pragma once

#include <set>
#include <string>

#include "bytes.hpp"
#include "descriptor.hpp"
#include "json.hpp"
#include "status.hpp"

// Encodes and decodes messages of a descriptor model in the OpenSchema wire format,
// converting from and to the JSON mapping of contract amendment 7 and enforcing types,
// required fields and constraints on both directions.
namespace nw {

struct CodecError {
  Status status = Status::Ok;
  // Where the problem is, e.g. "Event.attendees[2].email".
  std::string path;
  std::string reason;
};

struct EncodeOptions {
  // Only these ordinals are encoded and required; the object's other fields are ignored.
  // nullptr: every field of the model.
  const std::set<uint32_t>* fields = nullptr;
  // The message's previous encoding. Its unknown fields are kept, and so are those of a
  // replaced singular message field's previous value.
  ByteView previous;
  // Fields missing from the object keep their bytes from `previous`; a null value clears
  // the field. Otherwise a missing or null field is absent.
  bool keepMissing = false;
};

// InvalidArgument: the object does not fit the model (wrong type, unknown or missing
// field, failed constraint). Malformed: `previous` is not a valid encoding.
Result<Bytes> encodeMessage(const ModelDescriptor& model, const Json& object, const EncodeOptions& options,
                            CodecError& error);

// Decodes only the ordinals in `fields` (nullptr: every field). A known field outside
// `fields` is Malformed; unknown ordinals are skipped.
// Malformed: bad wire data, a missing required field or a failed constraint.
Result<Json> decodeMessage(const ModelDescriptor& model, ByteView bytes, const std::set<uint32_t>* fields,
                           CodecError& error);

}  // namespace nw
