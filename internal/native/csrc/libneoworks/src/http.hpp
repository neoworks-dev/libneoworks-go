#pragma once

#include <string>

#include "bytes.hpp"

namespace nw {

// Sans-IO: the host performs the HTTP requests and feeds responses back. The same
// engine therefore runs under native threads, wasm and Kotlin without callbacks
// into an event loop.
struct HttpRequest {
  std::string method;
  // Path and query below the API base when isApi, otherwise an absolute URL.
  std::string url;
  bool isApi = true;
  std::string contentType;
  Bytes body;
};

struct HttpResponse {
  int status = 0;
  Bytes body;
};

}  // namespace nw
