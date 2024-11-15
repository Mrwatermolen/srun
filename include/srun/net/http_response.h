#ifndef __SRUN_NET_HTTP_RESPONSE_H__
#define __SRUN_NET_HTTP_RESPONSE_H__

#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace srun::net {

class HttpResponse {
  static constexpr std::string_view CRLF = "\r\n";
  static constexpr std::string_view COLON = ": ";
  static constexpr std::string_view SPACE = " ";

 public:
  enum StatusCode : std::uint16_t {
    UNKNOW = 0,
    OK = 200,
    MOVED_PERMANENTLY = 301,
    MOVED_TEMPORARILY = 302,
    BAD_REQUEST = 400,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405
  };

  enum Version : std::uint8_t { UNKNOWN, HTTP_1_0, HTTP_1_1 };

  constexpr static auto versionFromString(std::string_view version) -> Version {
    if (version == "HTTP/1.0") {
      return HTTP_1_0;
    }
    if (version == "HTTP/1.1") {
      return HTTP_1_1;
    }
    return UNKNOWN;
  }

  constexpr static auto versionToString(Version version) -> std::string_view {
    switch (version) {
      case HTTP_1_0:
        return "HTTP/1.0";
      case HTTP_1_1:
        return "HTTP/1.1";
      default:
        return "UNKNOWN";
    }
  }

  constexpr static auto statusCodeToString(StatusCode status_code)
      -> std::string_view {
    switch (status_code) {
      case OK:
        return "OK";
      case MOVED_PERMANENTLY:
        return "Moved Permanently";
      case MOVED_TEMPORARILY:
        return "Moved Temporarily";
      case BAD_REQUEST:
        return "Bad Request";
      case NOT_FOUND:
        return "Not Found";
      case METHOD_NOT_ALLOWED:
        return "Method Not Allowed";
      default:
        return "Unknow";
    }
  }

  static auto makeOk() -> HttpResponse {
    auto response = HttpResponse{};
    response.setVersion(HTTP_1_1);
    response.setStatusCode(OK);
    response.addHeader("Content-Length", "0");
    return response;
  }

  static auto makeMovedPermanently() -> HttpResponse {
    auto response = HttpResponse{};
    response.setVersion(HTTP_1_1);
    response.setStatusCode(MOVED_PERMANENTLY);
    return response;
  }

  static auto makeBadRequest() -> HttpResponse {
    auto response = HttpResponse{};
    response.setStatusCode(BAD_REQUEST);
    response.setVersion(HTTP_1_1);
    response.addHeader("Content-Length", "0");
    return response;
  }

  static auto makeNotFound() -> HttpResponse {
    auto response = HttpResponse{};
    response.setVersion(HTTP_1_1);
    response.setStatusCode(NOT_FOUND);
    response.addHeader("Content-Length", "0");
    return response;
  }

  static auto makeMethodNotAllowed() -> HttpResponse {
    auto response = HttpResponse{};
    response.setVersion(HTTP_1_1);
    response.setStatusCode(METHOD_NOT_ALLOWED);
    response.addHeader("Content-Length", "0");
    return response;
  }

 public:
  auto version() const -> Version { return _version; }

  auto setVersion(Version version) -> void { _version = version; }

  auto statusCode() const -> StatusCode { return _status_code; }

  auto setStatusCode(StatusCode status_code) -> void {
    _status_code = status_code;
  }

  auto statusMessage() const { return _status_message; }

  auto setStatusMessage(std::string_view status_message) -> void {
    _status_message = status_message;
  }

  auto &headers() const { return _headers; }

  auto addHeader(std::string_view key, std::string_view value) -> void {
    _headers[std::string{key}] = std::string{value};
  }

  auto &body() const { return _body; }

  auto setBody(std::string_view body) -> void { _body = body; }

  auto toString() const -> std::string {
    auto ss = std::stringstream{};
    ss << versionToString(_version) << SPACE << statusCode() << SPACE
       << statusCodeToString(_status_code) << CRLF;

    for (const auto &[key, value] : _headers) {
      ss << key << COLON << value << CRLF;
    }
    ss << CRLF;

    ss << _body;

    return ss.str();
  }

  auto clear() -> void {
    _version = UNKNOWN;
    _status_code = UNKNOW;
    _headers.clear();
    _body.clear();
  }

  auto parseStateLine(std::string_view data) -> std::string::size_type {
    // Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF

    const auto pos = data.find(CRLF);
    if (pos == std::string::npos) {
      return pos;
    }

    auto status_line = data.substr(0, pos);

    const auto version_pos = status_line.find(SPACE);
    if (version_pos == std::string::npos) {
      return version_pos;
    }
    auto version = versionFromString(status_line.substr(0, version_pos));
    if (version == Version::UNKNOWN) {
      return version_pos;
    }
    setVersion(version);

    const auto code_pos = status_line.find(SPACE, version_pos + 1);
    if (code_pos == std::string::npos) {
      return code_pos;
    }
    auto code =
        std::stoi(std::string(status_line.substr(version_pos + 1, code_pos)));
    setStatusCode(static_cast<StatusCode>(code));

    setStatusMessage(status_line.substr(code_pos + 1));

    return pos + CRLF.size();  // skip CRLF
  }

  auto parseOneHeader(std::string_view data) -> std::string::size_type {
    const auto pos = data.find(CRLF);
    if (pos == std::string::npos) {
      return pos;
    }
    auto header = data.substr(0, pos);
    if (header.empty()) {
      return pos;
    }

    const auto colon_pos = header.find(COLON);
    if (colon_pos == std::string::npos) {
      return colon_pos;
    }
    auto key = header.substr(0, colon_pos);
    auto value = header.substr(colon_pos + 2);
    addHeader(key, value);

    return pos + CRLF.size();
  }

  auto parseHeaders(std::string_view data) -> std::string::size_type {
    if (data.empty()) {
      return std::string::npos;
    }

    std::string::size_type pos = 0;
    while (true) {
      if (data.empty()) {
        break;
      }

      auto bytes = parseOneHeader(data);
      if (bytes == std::string::npos) {
        return bytes;
      }
      if (bytes == 0) {
        break;
      }

      pos += bytes;
      data.remove_prefix(bytes);
    }

    return pos;
  }

 private:
  Version _version{UNKNOWN};
  StatusCode _status_code{UNKNOW};
  std::string _status_message;
  std::unordered_map<std::string, std::string> _headers;
  std::string _body;
};

}  // namespace srun::net

#endif  // __SRUN_NET_HTTP_RESPONSE_H__
