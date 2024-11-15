#include "net/http_session.h"

#include <iostream>

#include "srun/net/http_request.h"
#include "srun/net/http_response.h"
#include "net/http_response_parse.h"

namespace srun::net {

auto HttpSession::request(const HttpRequest &request) -> HttpResponse {
  auto buffer = Buffer{};
  buffer.append(request.encodeBytes());
  send(buffer);
  auto parse = HttpResponseParse{};
  parse.reset();

  try {
    while (parse.status() != HttpResponseParse::Status::OK) {
      parseResponse(readSome(), &parse);
    }
  } catch (const asio::system_error &e) {
    if (e.code() != asio::error::eof) {
      std::cerr << " request error: " << e.what() << "\n";
      throw e;
    }

    parseResponse(readBuffer(), &parse);
    if (parse.status() != HttpResponseParse::Status::OK) {
      std::cerr << "parse response error\n";
      parse.response().setStatusCode(HttpResponse::StatusCode::UNKNOW);
    }
  }

  auto res = std::move(parse.response());

  return res;
}

auto HttpSession::parseResponse(net::Buffer &buffer,
                                HttpResponseParse *parse) -> void {
  parse->run(buffer);
}

}  // namespace srun::net
