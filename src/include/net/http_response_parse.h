#ifndef __SRUN_NET_HTTP_RESPONSE_PARSE_H__
#define __SRUN_NET_HTTP_RESPONSE_PARSE_H__

#include <cstdint>
#include <limits>

#include "net/buffer.h"
#include "srun/net/http_response.h"

namespace srun::net {

class HttpResponseParse {
  static constexpr std::string_view CRLF = "\r\n";
  static constexpr std::string_view COLON = ": ";
  static constexpr std::string_view SPACE = " ";

 public:
  enum class Status : std::uint8_t { INVALID, StatusLine, Headers, Body, OK };

  auto status() const { return _status; }

  auto &response() const { return _response; }

  auto &response() { return _response; }

  auto reset() {
    _status = Status::StatusLine;
    _response.clear();
    _data.clear();
    _body_size = std::numeric_limits<std::size_t>::max();
  }

  auto markAsInvalid() {
    _status = Status::INVALID;
    _response.clear();
    _data.clear();
    _body_size = std::numeric_limits<std::size_t>::max();
  }

  auto run(net::Buffer &buffer) {
    if (buffer.empty()) {
      return;
    }

    if (status() == Status::INVALID || status() == Status::OK) {
      buffer.retrieve(buffer.readableBytes());  // clear buffer
      return;
    }

    _data += buffer.retrieveAllAsString();
    while (parse()) {
    }
  }

 private:
  auto parse() -> bool {
    switch (status()) {
      case Status::StatusLine: {
        const auto bytes = _response.parseStateLine(_data);
        if (bytes == std::string::npos) {
          return false;
        }

        _data.erase(0, bytes);
        _status = Status::Headers;
        return !_data.empty();
      }
      case Status::Headers: {
        const auto bytes = _response.parseHeaders(_data);
        if (bytes == std::string::npos) {
          return false;
        }

        auto it = _response.headers().find("Content-Length");
        if (it != _response.headers().end()) {
          _body_size = std::stoul(it->second);
        } else {
          _body_size = 0;
        }

        if (bytes == 0) {
          _status = Status::Body;
          auto it = _response.headers().find("Content-Length");
          if (it != _response.headers().end()) {
            _body_size = std::stoul(it->second);
          } else {
            _body_size = 0;
          }

          return !_data.empty();
        }

        _data.erase(0, bytes);
        _status = Status::Body;
        return !_data.empty();
      }
      case Status::Body: {
        if (_body_size == 0) {
          _status = Status::OK;
          return false;
        }

        if (!_data.empty() && _data.substr(0, 2) == CRLF) {
          _data.erase(0, 2);
        }

        if (_data.size() < _body_size) {
          return false;
        }

        _response.setBody(_data.substr(0, _body_size));
        _data.clear();
        _status = Status::OK;
        return false;
      }
      default:
        break;
    }

    return false;
  }

 private:
  Status _status{Status::StatusLine};
  HttpResponse _response;
  std::string _data;
  std::size_t _body_size{std::numeric_limits<std::size_t>::max()};
};

}  // namespace srun::net

#endif  // __SRUN_NET_HTTP_RESPONSE_PARSE_H__
