#ifndef __SRUN_HPP__
#define __SRUN_HPP__

#define SRUN_SSL_ENABLED 1

#include <openssl/hmac.h>

#include <asio.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <nlohmann/json_fwd.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#if SRUN_SSL_ENABLED
#include <asio/ssl.hpp>
#endif

namespace srun {

namespace utl {
inline auto md5(const std::string &key, const std::string &data) {
  unsigned char *result;
  static const size_t hash_len = EVP_MD_size(EVP_md5());
  result = static_cast<unsigned char *>(malloc(hash_len));

  HMAC(EVP_md5(), key.c_str(), key.length(),
       reinterpret_cast<const unsigned char *>(data.c_str()), data.length(),
       result, nullptr);

  std::ostringstream oss;
  for (size_t i = 0; i < hash_len; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(result[i]);
  }

  free(result);
  return oss.str();
}

inline auto sha1(std::string_view data) {
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const unsigned char *>(data.data()), data.size(), hash);

  std::ostringstream oss;
  for (unsigned char i : hash) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
  }

  return oss.str();
}

inline auto base64Encode(std::string_view input,
                         std::string_view base64_chars) -> std::string {
  std::string encoded;
  int val = 0;
  int valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  }
  while ((encoded.size() % 4) != 0U) {
    encoded.push_back('=');
  }
  return encoded;
}

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

}  // namespace utl

namespace net {

class Buffer;
class Session;

using ConnectCallback = std::function<void(std::shared_ptr<Session>)>;
using DisconnectCallback = std::function<void(std::shared_ptr<Session>)>;

class Buffer {
 public:
  static constexpr std::size_t DEFAULT_SIZE = 1024;

  auto capacity() const { return _buffer.size(); }

  auto empty() const { return _writer_pos == _reader_pos; }

  auto full() const { return _writer_pos == _buffer.size(); }

  auto writeableBytes() const { return _buffer.size() - _writer_pos; }

  auto readableBytes() const { return _writer_pos - _reader_pos; }

  auto writeBegin() { return _buffer.data() + _writer_pos; }

  auto writeEnd() { return _buffer.data() + _buffer.size(); }

  auto readBegin() { return _buffer.data() + _reader_pos; }

  auto readEnd() { return _buffer.data() + _writer_pos; }

  auto readBegin() const { return _buffer.data() + _reader_pos; }

  auto readEnd() const { return _buffer.data() + _writer_pos; }

  auto hasWritten(std::size_t len) {
    _writer_pos += len;
    return _writer_pos;
  }

  auto append(const char *data, std::size_t len) {
    if (writeableBytes() < len) {
      auto new_size = std::max(_buffer.size() * 2, _buffer.size() + len);
      _buffer.resize(new_size);
    }

    std::copy(data, data + len, writeBegin());
    _writer_pos += len;
  }

  auto append(std::string_view data) { append(data.data(), data.size()); }

  auto append(const char *data) { append(data, std::strlen(data)); }

  auto append(char data) { append(&data, 1); }

  auto retrieve(std::size_t len) {
    if (readableBytes() <= len) {
      retrieveAll();
      return;
    }

    _reader_pos += len;
  }

  auto retrieveUntil(const char *end) {
    assert(readBegin() <= end);
    retrieve(end - readBegin());
  }

  auto retrieveAllAsString() {
    auto str = std::string{readBegin(), readableBytes()};
    retrieveAll();
    return str;
  }

  auto resize(std::size_t len) -> void {
    if (empty()) {
      retrieveAll();
      _buffer.resize(len);
      return;
    }

    if (len <= writeableBytes()) {
      return;
    }

    _buffer.resize(_buffer.size() + len);
  }

 private:
  auto retrieveAll() -> void {
    _reader_pos = 0;
    _writer_pos = 0;
  }

 private:
  std::size_t _writer_pos{};
  std::size_t _reader_pos{};
  std::vector<char> _buffer = std::vector<char>(DEFAULT_SIZE, 0);
};

class Session : public std::enable_shared_from_this<Session> {
 public:
  explicit Session(asio::io_context &io_context)
      : _io_context{io_context},
#if SRUN_SSL_ENABLED
        _ssl_context{asio::ssl::context::sslv23},
        _socket{_io_context, _ssl_context}
#else
        _socket{_io_context}
#endif
  {
  }

  virtual ~Session() = default;

  auto &socket() { return _socket; }

  auto &socket() const { return _socket; }

  auto &writeBuffer() { return _write_buffer; }

  auto &readBuffer() { return _read_buffer; }

  auto &writeBuffer() const { return _write_buffer; }

  auto &readBuffer() const { return _read_buffer; }

  auto disconnect() -> void {}

  auto setConnectCallback(
      std::function<void(std::shared_ptr<Session>)> callback) {
    _connect_callback = std::move(callback);
  }

  auto setDisconnectCallback(
      std::function<void(std::shared_ptr<Session>)> callback) {
    _disconnect_callback = std::move(callback);
  }

  auto connect(std::string_view host, std::string_view service) -> void {
    auto self = shared_from_this();
    auto resolver = asio::ip::tcp::resolver{_io_context};
    auto query = asio::ip::tcp::resolver::query{host.data(), service.data()};

    auto endpoints = resolver.resolve(query);

#if SRUN_SSL_ENABLED
    auto &&socket = this->socket().lowest_layer();
#else
    auto &&socket = this->socket();
#endif

    socket.connect(*endpoints.begin());
    _connect_callback(shared_from_this());
  }

  auto &readSome() {
    if (_read_buffer.empty()) {
      _read_buffer.resize(Buffer::DEFAULT_SIZE);
    }

    try {
      auto len = socket().read_some(asio::buffer(
          _read_buffer.writeBegin(), _read_buffer.writeableBytes()));
      _read_buffer.hasWritten(len);
      return _read_buffer;
    } catch (const asio::system_error &e) {
      if (e.code() != asio::error::eof) {
        std::cerr << "read error: " << e.what() << "\n";
      }

      throw e;
    }
  }

  auto send(const Buffer &buffer) -> void {
    _write_buffer.append(buffer.readBegin(), buffer.readableBytes());
    try {
      while (_write_buffer.readableBytes() > 0) {
        auto len = socket().write_some(asio::buffer(
            _write_buffer.readBegin(), _write_buffer.readableBytes()));
        _write_buffer.retrieve(len);
      }
    } catch (const asio::system_error &e) {
      if (e.code() != asio::error::eof) {
        std::cerr << "send error: " << e.what() << "\n";
      }

      throw e;
    }
  }

 private:
  asio::io_context &_io_context;
#if SRUN_SSL_ENABLED
  asio::ssl::context _ssl_context;
  asio::ssl::stream<asio::ip::tcp::socket> _socket;
#else
  asio::ip::tcp::socket _socket;
#endif
  Buffer _read_buffer;
  Buffer _write_buffer;
  ConnectCallback _connect_callback;
  DisconnectCallback _disconnect_callback;
};

constexpr inline std::string_view CRLF = "\r\n";
constexpr inline std::string_view COLON = ": ";
constexpr inline std::string_view SPACE = " ";

class HttpRequest {
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

  auto toString() const -> std::string {
    std::stringstream ss;
    ss << methodToString(_method) << SPACE << _path;
    if (!_querys.empty()) {
      ss << "?";
      for (const auto &[key, value] : _querys) {
        ss << utl::urlEncode(key) << "=" << utl::urlEncode(value) << "&";
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

class HttpResponse {
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
    auto code = std::stoi(status_line.substr(version_pos + 1, code_pos).data());
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

class HttpResponseParse {
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

class HttpSession : public Session {
 public:
  auto &request(const HttpRequest &request) {
    auto buffer = Buffer{};
    buffer.append(request.toString());
    send(buffer);

    _http_response_parse.reset();

    try {
      while (_http_response_parse.status() != HttpResponseParse::Status::OK) {
        parseResponse(readSome());
      }
    } catch (const asio::system_error &e) {
      if (e.code() != asio::error::eof) {
        std::cerr << " request error: " << e.what() << "\n";
        throw e;
      }

      parseResponse(readBuffer());
      if (_http_response_parse.status() != HttpResponseParse::Status::OK) {
        std::cerr << "parse response error\n";
        _http_response_parse.response().setStatusCode(
            HttpResponse::StatusCode::UNKNOW);
      }
    }

    return _http_response_parse.response();
  }

  auto parseResponse(net::Buffer &buffer) -> void {
    _http_response_parse.run(buffer);
  }

  auto &httpResponseParse() const { return _http_response_parse; }

  auto &httpResponseParse() { return _http_response_parse; }

  using Session::Session;

 private:
  HttpResponseParse _http_response_parse{};
};

}  // namespace net

namespace encode {

inline auto mix(std::string_view data, bool size_in_back) {
  std::uint32_t c = data.size();
  std::vector<std::uint32_t> v;
  v.resize((c >> 2));

  for (std::size_t i = 0; i < c; i += 4) {
    v[i >> 2] =
        data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24;
  }

  if (size_in_back) {
    v.push_back(c);
  }
  return v;
}

inline auto split(const std::vector<std::uint32_t> &buffer,
                  bool size_in_back) -> std::string {
  auto len = buffer.size();
  auto size = ((len - 1) << 2);
  std::string result;
  if (size_in_back) {
    if (buffer.back() < size - 3 || size < buffer.back()) {
      return result;
    }

    size = buffer.back();
  }

  for (std::size_t i = 0; i < len; ++i) {
    result.push_back(buffer[i] & 0xff);
    result.push_back((buffer[i] >> 8) & 0xff);
    result.push_back((buffer[i] >> 16) & 0xff);
    result.push_back((buffer[i] >> 24) & 0xff);
  }

  if (size_in_back) {
    return result.substr(0, size);
  }

  return result;
}

inline auto encode(const std::string_view key,
                   std::string_view data) -> std::string {
  if (data.empty()) {
    return "";
  }

  auto v = mix(data, true);
  auto k = mix(key, false);
  if (k.size() < 4) {
    for (std::size_t i = k.size(); i < 4; ++i) {
      k.push_back(0);
    }
  }

  auto len = v.size();
  auto last = len - 1;
  std::uint32_t c = 0x86014019 | 0x183639A0;
  std::uint32_t d = 0;
  std::uint64_t left = v.front();
  std::uint64_t right = v.back();
  std::uint64_t m = 0;

  auto count = 6 + 52 / len;

  for (std::size_t i = 0; i < count; ++i) {
    auto f = (0x8CE0D9BF | 0x731F2640);
    d = d + c & (0x8CE0D9BF | 0x731F2640);
    auto e = (d >> 2) & 3;
    for (std::size_t p = 0; p < last; ++p) {
      left = v[p + 1];
      m = (right >> 5) ^ (left << 2);
      m += (left >> 3) ^ (right << 4) ^ (d ^ left);
      m += k[(p & 3) ^ e] ^ right;
      v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF);
      right = v[p];
    }

    left = v[0];
    m = (right >> 5) ^ (left << 2);
    m += (left >> 3) ^ (right << 4) ^ (d ^ left);
    m += k[(last & 3) ^ e] ^ right;
    v[last] = v[last] + m & (0xBB390742 | 0x44C6F8BD);
    right = v[last];
  }
  std::vector<std::int32_t> u_t{v.begin(), v.end()};

  return split(v, false);
}

}  // namespace encode

struct ErrResponse {
  ErrResponse() = default;

  explicit ErrResponse(std::string_view data) {
    auto json = nlohmann::json::parse(data);
    if (json.contains("error")) {
      _error = json["error"];
    }

    if (json.contains("ecode")) {
      if (json["ecode"].is_number()) {
        _ecode = json["ecode"];
      } else {
        _ecode = 0;
      }
    }

    if (json.contains("error_msg")) {
      _error_msg = json["error_msg"];
    }

    if (!_error.empty()) {
      _ecode = 0;
    }
  }

  auto ok() const { return _ecode == 0 && _error == "ok"; }

  auto errMsg() const -> std::string {
    if (ok()) {
      return "ok";
    }

    return _error_msg.empty() ? _error : _error_msg;
  }

  auto ecode() const { return _ecode; }

  auto error() const { return _error; }

  auto errorMsg() const { return _error_msg; }

  int _ecode{-1};
  std::string _error_msg;
  std::string _error;
};

struct InfoResponse {
  explicit InfoResponse(const net::HttpResponse &response) {
    std::string_view body = response.body();
    auto json = nlohmann::json::parse(body);
    try {
      _err_response = ErrResponse{body};
      if (!_err_response.ok()) {
        if (json.contains("client_ip")) {
          _client_ip = json["client_ip"];
        }

        if (json.contains("online_ip")) {
          _online_ip = json["online_ip"];
        }

        if (_online_ip.empty()) {
          _online_ip = _client_ip;
        }

        if (_client_ip.empty()) {
          _client_ip = _online_ip;
        }
        return;
      }

      _online_ip = json["online_ip"];
      _client_ip = _online_ip;
      _add_time = json["add_time"];
      _billing_name = json["billing_name"];
      _bytes_in = json["bytes_in"];
      _bytes_out = json["bytes_out"];
      _keepalive_time = json["keepalive_time"];
      _products_id = json["products_id"];
      _products_name = json["products_name"];
      _remain_bytes = json["remain_bytes"];
      _remain_seconds = json["remain_seconds"];
      _sum_bytes = json["sum_bytes"];
      _sum_seconds = json["sum_seconds"];
      _user_balance = json["user_balance"];
      _user_charge = json["user_charge"];
      _username = json["user_name"];
    } catch (const std::exception &e) {
      std::cerr << "parse info response error: " << e.what() << "\n";
      return;
    }
  }

  auto ok() const { return _err_response.ok(); }

  auto errResponse() const { return _err_response; }

  auto onlineIp() const { return _online_ip; }

  auto clientIp() const { return _client_ip; }

  auto addTime() const { return _add_time; }

  auto billingName() const { return _billing_name; }

  auto bytesIn() const { return _bytes_in; }

  auto bytesOut() const { return _bytes_out; }

  auto keepAliveTime() const { return _keepalive_time; }

  auto productId() const { return _products_id; }

  auto productName() const { return _products_name; }

  auto remainBytes() const { return _remain_bytes; }

  auto remainSeconds() const { return _remain_seconds; }

  auto sumBytes() const { return _sum_bytes; }

  auto sumSeconds() const { return _sum_seconds; }

  auto userBalance() const { return _user_balance; }

  auto userCharge() const { return _user_charge; }

  auto username() const { return _username; }

  ErrResponse _err_response;

  std::string _online_ip;

  std::string _client_ip;
  std::size_t _add_time;
  std::string _billing_name;
  std::size_t _bytes_in{};
  std::size_t _bytes_out{};
  std::size_t _keepalive_time{};
  std::string _products_id;
  std::string _products_name;
  std::size_t _remain_bytes{};
  std::size_t _remain_seconds{};
  std::size_t _sum_bytes{};
  std::size_t _sum_seconds{};
  std::size_t _user_balance{};
  std::size_t _user_charge{};
  std::string _username;
};

struct ChallengeResponse {
  explicit ChallengeResponse(const net::HttpResponse &response) {
    std::string_view body = response.body();
    auto json = nlohmann::json::parse(body);

    try {
      _err_response = ErrResponse{body};

      _client_ip = json["client_ip"];
      _online_ip = json["online_ip"];

      if (!_err_response.ok()) {
        return;
      }

      _challenge = json["challenge"];
      _expire = json["expire"];
    } catch (const std::exception &e) {
      std::cerr << "parse challenge response error: " << e.what() << "\n";
    }
  }

  auto ok() const { return _err_response.ok(); }

  auto errResponse() const { return _err_response; }

  auto challenge() const { return _challenge; }

  auto clientIp() const { return _client_ip; }

  auto expire() const { return _expire; }

  auto onlineIp() const { return _online_ip; }

  ErrResponse _err_response;

  std::string _client_ip;
  std::string _online_ip;

  std::string _expire;
  std::string _challenge;
};

class SRunClient {
 public:
  static constexpr std::string_view CHALLENGE_PATH = "/cgi-bin/get_challenge";
  static constexpr std::string_view INFO_PATH = "/cgi-bin/rad_user_info";
  static constexpr std::string_view AUTH_PATH = "/cgi-bin/srun_portal";

 public:
  explicit SRunClient(std::string_view config_path) {
    if (!std::filesystem::exists(config_path) ||
        !std::filesystem::is_regular_file(config_path)) {
      std::stringstream ss;
      ss << "SRunClient init error: can't find config file: " << config_path;
      throw std::runtime_error(ss.str());
    }

    auto ifs = std::ifstream{config_path.data()};
    if (!ifs.is_open()) {
      std::stringstream ss;
      ss << "SRunClient init error: can't open config file: " << config_path;
      throw std::runtime_error(ss.str());
    }

    auto json = nlohmann::json{};
    ifs >> json;

    try {
      auto protocol = json.at("protocol");
      if (protocol == "https") {
#ifndef SRUN_SSL_ENABLED
        throw std::runtime_error("SRunClient init error: SSL don't support.");
#endif
        _ssl = true;
      }

      unsigned port = json.at("port");
      _port = std::to_string(port);
      _host = json.at("host");
      _username = json.at("username");
      _password = json.at("password");
    } catch (const std::out_of_range &e) {
      throw std::runtime_error(
          std::string(
              "SRunClient init error: missing required field in config. ") +
          e.what());
    }

    if (json.contains("ip")) {
      _ip = json["ip"];
    }

    if (json.contains("ac_id")) {
      _ac_id = json["ac_id"];
    }
  }

  auto host() const { return _host; }

  auto service() const { return _port; }

  auto username() const { return _username; }

  auto setUsername(std::string_view username) -> void { _username = username; }

  auto password() const { return _password; }

  auto setPassword(std::string_view password) -> void { _password = password; }

  auto ip() const { return _ip; }

  auto setIp(std::string_view ip) -> void { _ip = ip; }

  auto acId() const { return _ac_id; }

  auto setAcId(std::size_t ac_id) -> void { _ac_id = ac_id; }

  auto n() const { return _n; }

  auto setN(std::size_t n) -> void { _n = n; }

  auto type() const { return _type; }

  auto setType(std::size_t type) -> void { _type = type; }

  auto os() const { return _os; }

  auto setOs(std::string_view os) -> void { _os = os; }

  auto osName() const { return _os_name; }

  auto setOsName(std::string_view os_name) -> void { _os_name = os_name; }

  auto doubleStack() const { return _double_stack; }

  auto setDoubleStack(bool double_stack) -> void {
    _double_stack = static_cast<int>(double_stack);
  }

  auto ioContext() -> asio::io_context & { return _io_context; }

  auto checkOnline() -> bool {
    try {
      auto request = net::HttpRequest{};
      auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
      request.addQuery("_", std::to_string(unix_time));

      auto &&response = api(INFO_PATH, request);

      if (response.statusCode() != net::HttpResponse::OK) {
        std::cerr << "check online error: " << response.statusMessage() << "\n";
        return false;
      }

      auto info = InfoResponse{response};
      return info.ok();
    } catch (const asio::system_error &e) {
      std::cerr << "check online error: " << e.what() << "\n";
    }

    return false;
  }

  auto getInfo() -> InfoResponse {
    auto request = net::HttpRequest{};
    auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    request.addQuery("_", std::to_string(unix_time));

    auto &&response = api(INFO_PATH, request);

    if (response.statusCode() != net::HttpResponse::OK) {
      std::cerr << "check online error: " << response.statusMessage() << "\n";
      throw std::runtime_error("get info error");
    }

    return InfoResponse{response};
  }

  auto getChallenge() -> ChallengeResponse {
    if (_ip.empty()) {
      throw std::runtime_error("get challenge error: no ip");
    }

    auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    auto request = net::HttpRequest{};
    request.addQuery("ip", _ip);
    request.addQuery("username", _username);
    request.addQuery("_", std::to_string(unix_time));

    auto &&response = api(CHALLENGE_PATH, request);
    if (response.statusCode() != net::HttpResponse::OK) {
      throw std::runtime_error("get challenge error: " +
                               response.statusMessage());
    }

    return ChallengeResponse{response};
  }

  auto login() -> void {
    if (_ip.empty()) {
      fetchIp();
    }

    auto challenge = getChallenge();

    if (!challenge.ok()) {
      throw std::runtime_error("login error: " +
                               challenge.errResponse().errMsg());
    }

    auto token = challenge.challenge();

    auto param_i = paramI(_username, _password, _ip, _ac_id, token);
    auto hmd5 = utl::md5(token, _password);

    auto str = token + _username;
    str += token + hmd5;
    str += token + std::to_string(_ac_id);
    str += token + _ip;
    str += token + std::to_string(_n);
    str += token + std::to_string(_type);
    str += token + param_i;
    auto sha1 = utl::sha1(str);

    auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    auto request = net::HttpRequest{};
    request.addQuery("action", "login");
    request.addQuery("username", _username);
    request.addQuery("password", "{MD5}" + hmd5);
    request.addQuery("ac_id", std::to_string(_ac_id));
    request.addQuery("ip", _ip);
    request.addQuery("chksum", sha1);
    request.addQuery("info", param_i);
    request.addQuery("n", std::to_string(_n));
    request.addQuery("type", std::to_string(_type));
    request.addQuery("os", _os);
    request.addQuery("name", _os_name);
    request.addQuery("double_stack", std::to_string(_double_stack));
    request.addQuery("_", std::to_string(unix_time));
    auto &&response = api(AUTH_PATH, request);
    request.setPath(AUTH_PATH);

    if (response.statusCode() != net::HttpResponse::OK) {
      throw std::runtime_error("login error: " + response.statusMessage());
    }

    auto err_response = ErrResponse{response.body()};
    if (!err_response.ok()) {
      throw std::runtime_error("login error: " + err_response.errMsg());
    }
  }

  auto logout() -> void {
    if (_ip.empty()) {
      fetchIp();
    }

    auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    auto request = net::HttpRequest{};
    request.addQuery("action", "logout");
    request.addQuery("username", _username);
    request.addQuery("ac_id", std::to_string(_ac_id));
    request.addQuery("ip", _ip);
    request.addQuery("_", std::to_string(unix_time));

    auto &&response = api(AUTH_PATH, request);
    if (response.statusCode() != net::HttpResponse::OK) {
      throw std::runtime_error("logout error: " + response.statusMessage());
    }

    auto err_response = ErrResponse{response.body()};

    if (!err_response.ok()) {
      throw std::runtime_error("logout error: " + err_response.errMsg());
    }
  }

  auto fetchIp() -> void {
    auto info = getInfo();
    if (info.errResponse().ecode() != 0) {
      throw std::runtime_error("fetch ip error: " +
                               info.errResponse().errMsg());
    }

    _ip = info.clientIp();

    if (_ip.empty()) {
      throw std::runtime_error("fetch ip error: no ip");
    }
  }

  auto api(std::string_view path,
           net::HttpRequest request) -> net::HttpResponse {
    request.setMethod(net::HttpRequest::Method::GET);
    request.setPath(path);
    request.setVersion(net::HttpRequest::Version::HTTP_1_1);
    request.addHeader("Host", _host);
    request.addQuery("callback", "null");

    auto buffer = net::Buffer{};
    buffer.append(request.toString());

    auto session = newHttpClient();
    session->connect(_host, _port);

    auto &&res = session->request(request);
    // remove "null" and "(" and ")"
    if (5 < res.body().size()) {
      res.setBody(res.body().substr(5, res.body().size() - 6));
    }

    return res;
  }

 private:
  auto newHttpClient() -> std::shared_ptr<net::HttpSession> {
    auto session = std::make_shared<net::HttpSession>(_io_context);
    if (_ssl) {
#ifndef SRUN_SSL_ENABLED
      throw std::runtime_error("new https session error: SSL don't support.");
#endif
      session->setConnectCallback(
          [this](const std::shared_ptr<net::Session> &session) {
            session->socket().handshake(asio::ssl::stream_base::client);
          });
    }
    return session;
  }

  auto paramI(std::string_view username, std::string_view password,
              std::string_view ip, int ac_id,
              std::string_view token) -> std::string {
    std::string info;
    info += "{";
    info += R"("username":")";
    info += username;
    info += "\",";
    info += R"("password":")";
    info += password;
    info += "\",";
    info += R"("ip":")";
    info += ip;
    info += "\",";
    info += R"("acid":")";
    info += std::to_string(ac_id) + "\",";
    info += R"("enc_ver":")";
    info += "srun_bx1\"";
    info += "}";

    return "{SRBX1}" +
           utl::base64Encode(encode::encode(token, info),
                             "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/"
                             "3dlbfKwv6xztjI7DeBE45QA");
  }

 private:
  asio::io_context _io_context;

  bool _ssl{false};
  std::string _host;
  std::string _port;
  std::string _username;
  std::string _password;

  std::string _ip;
  int _ac_id{1};
  int _n{200};
  int _type{1};
  std::string _os{"Linux"};
  std::string _os_name{"Linux"};
  int _double_stack{0};
};

}  // namespace srun

#endif  // __SRUN_HPP__
