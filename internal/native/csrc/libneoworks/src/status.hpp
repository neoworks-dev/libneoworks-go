#pragma once

#include <utility>

namespace nw {

// Values mirror the NW_ERR_* constants in neoworks.h.
enum class Status : int {
  Ok = 0,
  InvalidArgument = 1,
  Malformed = 2,
  AuthenticationFailed = 3,
  NotFound = 4,
  CryptoFailure = 5,
  Expired = 6,
  Unsupported = 7,
  InvalidState = 8,
  IoFailure = 9,
  Conflict = 10,
  Forbidden = 11,
  ResyncRequired = 12,
  Internal = 13,
  IntegrityFailure = 14,
};

template <typename Value>
class Result {
 public:
  Result(Value value) : status_(Status::Ok), value_(std::move(value)) {}
  Result(Status failure) : status_(failure), value_() {}

  bool ok() const { return status_ == Status::Ok; }
  Status status() const { return status_; }
  Value& value() { return value_; }
  const Value& value() const { return value_; }
  Value take() { return std::move(value_); }

 private:
  Status status_;
  Value value_;
};

}  // namespace nw
