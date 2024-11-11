#ifndef __SRUN_NET_HTTP_SESSION_H__
#define __SRUN_NET_HTTP_SESSION_H__

#include "net/session.h"

namespace srun::net {

class Buffer;
class Session;
class HttpRequest;
class HttpResponse;
class HttpResponseParse;

class HttpSession : public Session {
 public:
  auto request(const HttpRequest &request) -> HttpResponse;

  using Session::Session;

 private:
  auto parseResponse(net::Buffer &buffer, HttpResponseParse *parse) -> void;
};

}  // namespace srun::net

#endif  // __SRUN_NET_HTTP_SESSION_H__
