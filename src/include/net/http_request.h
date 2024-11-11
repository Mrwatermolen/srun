#ifndef __SRUN_NET_HTTP_REQUEST_H__
#define __SRUN_NET_HTTP_REQUEST_H__

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace srun::net {

inline auto urlEncode(std::string_view data) {
  std::ostringstream oss;

  for (auto c : data) {
    if ((std::isalnum(c) != 0) || c == '-' || c == '_' || c == '.' ||
        c == '~') {
      oss << c;
      continue;
    }

    oss << '%' << std::uppercase << std::hex << std::setw(2)
        << std::setfill('0') << static_cast<int>(c);
  }

  return oss.str();
}

inline auto urlDecode(std::string_view data) {
  std::ostringstream oss;

  for (std::size_t i = 0; i < data.size(); ++i) {
    if (data[i] == '%') {
      if (i + 2 < data.size()) {
        auto c = static_cast<char>(
            std::stoi(std::string(data.substr(i + 1, 2)), nullptr, 16));
        oss << c;
        i += 2;
      }
    } else {
      oss << data[i];
    }
  }

  return oss.str();
}

class HttpRequest {
  static constexpr inline std::string_view CRLF = "\r\n";
  static constexpr inline std::string_view COLON = ": ";
  static constexpr inline std::string_view SPACE = " ";

 public:
  enum Method : std::uint8_t { INVALID, GET, POST, PUT, kDELETE, HEAD };

  enum Version : std::uint8_t { UNKNOWN, HTTP_1_0, HTTP_1_1 };

  constexpr static auto methodToString(Method method) -> std::string_view {
    switch (method) {
      case GET:
        return "GET";
      case POST:
        return "POST";
      case PUT:
        return "PUT";
      case kDELETE:
        return "DELETE";
      case HEAD:
        return "HEAD";
      default:
        return "INVALID";
    }
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

  constexpr static auto methodFromString(std::string_view method) -> Method {
    if (method == "GET") {
      return GET;
    }
    if (method == "POST") {
      return POST;
    }
    if (method == "PUT") {
      return PUT;
    }
    if (method == "DELETE") {
      return kDELETE;
    }
    if (method == "HEAD") {
      return HEAD;
    }
    return INVALID;
  }

  constexpr static auto versionFromString(std::string_view version) -> Version {
    if (version == "HTTP/1.0") {
      return HTTP_1_0;
    }
    if (version == "HTTP/1.1") {
      return HTTP_1_1;
    }
    return UNKNOWN;
  }

 public:
  auto method() const { return _method; }

  auto setMethod(Method method) { _method = method; }

  auto path() const { return _path; }

  auto setPath(std::string_view path) { _path = path; }

  auto &querys() const { return _querys; }

  auto addQuery(std::string_view key, std::string_view value) {
    _querys.emplace(key, value);
  }

  auto version() const { return _version; }

  auto setVersion(Version version) { _version = version; }

  auto &headers() const { return _headers; }

  auto addHeader(std::string_view key, std::string_view value) {
    _headers[std::string{key}] = std::string{value};
  }

  auto &body() const { return _body; }

  auto setBody(std::string_view body) { _body = body; }

  auto keepAlive() const -> bool {
    auto connection = _headers.find("Connection");
    if (connection == _headers.end()) {
      return false;
    }
    return connection->second == "keep-alive";
  }

  auto clear() -> void {
    _method = INVALID;
    _path.clear();
    _querys.clear();
    _version = UNKNOWN;
    _headers.clear();
    _body.clear();
  }

  auto encodeBytes() const -> std::string {
    std::stringstream ss;
    ss << methodToString(_method) << SPACE << _path;
    if (!_querys.empty()) {
      ss << "?";
      for (const auto &[key, value] : _querys) {
        ss << urlEncode(key) << "=" << urlEncode(value) << "&";
      }
      ss.seekp(-1, std::ios_base::end);
    }

    ss << SPACE << versionToString(_version) << CRLF;

    for (const auto &[key, value] : _headers) {
      ss << key << COLON << value << CRLF;
    }
    ss << CRLF;

    ss << _body;

    return ss.str();
  }

 private:
  Method _method{Method::INVALID};
  std::string _path;
  std::unordered_map<std::string, std::string> _querys;
  Version _version{Version::UNKNOWN};
  std::unordered_map<std::string, std::string> _headers;
  std::string _body;
};

}  // namespace srun::net

#endif  // __SRUN_NET_HTTP_REQUEST_H__
