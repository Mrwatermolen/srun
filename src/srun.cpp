#include "srun/srun.h"

#include <algorithm>
#include <asio.hpp>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>
#include <string_view>

#ifdef SRUN_SSL_ENABLED
#include <asio/ssl.hpp>
#endif

#include "encode.h"
#include "net/http_session.h"
#include "srun/common.h"
#include "srun/exception.h"
#include "srun/net/http_request.h"
#include "srun/net/http_response.h"
#include "util.h"

namespace srun {

auto SrunClient::init(std::string_view config_path) -> void {
  if (!std::filesystem::exists(config_path)) {
    throw SrunException(std::format("Can't find config file: {}", config_path));
  }

  if (!std::filesystem::is_regular_file(config_path)) {
    throw SrunException(
        std::format("Config file is not a regular file: {}", config_path));
  }

  auto ifs = std::ifstream{std::string{config_path}};
  if (!ifs.is_open()) {
    std::stringstream ss;
    ss << "Can't open config file: " << config_path;
    throw SrunException(ss.str());
  }

  auto json = nlohmann::json{};

  try {
    ifs >> json;
  } catch (const nlohmann::json::parse_error& e) {
    throw SrunException(
        std::format("File {} parse error: {}", config_path, e.what()));
  }

  if (!json.contains("host")) {
    throw SrunException("Missing required field host in config file");
  }

  if (json.contains("protocol")) {
    std::string protocol = json["protocol"];
    _ssl = std::ranges::equal(
        protocol, std::string("https"),
        [](char a, char b) { return std::tolower(a) == std::tolower(b); });

#ifndef SRUN_SSL_ENABLED
    if (_ssl) {
      throw SrunSSLDisabledException{};
    }
#endif
  }

  _host = json["host"];

  if (json.contains("port")) {
    _port = std::to_string(static_cast<std::uint16_t>(json["port"]));
  } else {
    _port = (_ssl ? "443" : "80");
  }

  if (json.contains("username")) {
    _username = json["username"];
  }

  if (json.contains("password")) {
    _password = json["password"];
  }

  if (json.contains("ip")) {
    _auto_ip = false;
    _ip = json["ip"];
  } else {
    _auto_ip = true;
  }

  if (json.contains("ac_id")) {
    _auto_ac_id = false;
    _ac_id = json["ac_id"];
  } else {
    _auto_ac_id = true;
  }

  if (json.contains("os")) {
    _os = json["os"];
  }

  if (json.contains("os_name")) {
    _os_name = json["os_name"];
  }
}

auto SrunClient::fetchAcId() -> int {
#ifndef SRUN_SSL_ENABLED
  if (_ssl) {
    throw SrunSSLDisabledException{};
  }
#endif
  int ac_id = 1;  // default 1
  auto session = newHttpClient();
  auto request = net::HttpRequest{};
  request.setMethod(net::HttpRequest::Method::GET);
  request.setVersion(net::HttpRequest::Version::HTTP_1_1);
  request.addHeader("Host", _host);
  request.setPath("/");
  session->connect(_host, _port);
  auto res = session->request(request);
  if (res.statusCode() != net::HttpResponse::StatusCode::MOVED_TEMPORARILY) {
    return ac_id;
  }

  auto url = res.headers().find("Location")->second;

  auto find_ac_id = [](auto&& data) {
    auto pos = data.find("ac_id");
    std::optional<int> ac_id;
    if (pos == std::string::npos) {
      return ac_id;
    }

    auto v_start = data.find('=', pos);
    auto v_end = (data.find('&', v_start));
    if (v_end == std::string::npos) {
      v_end = data.size();
    }
    ac_id = std::stoi(data.substr(v_start + 1, v_end));

    return ac_id;
  };

  {
    auto i = find_ac_id(url);
    if (i.has_value()) {
      ac_id = i.value();
      return ac_id;
    }
  }

  auto url_regex = std::regex{R"((https?)://([^/]+)(/.*)?$)"};
  std::smatch match;
  if (!std::regex_match(url, match, url_regex)) {
    return ac_id;
  }

  auto host = match[2].str();
  auto path = match[3].str().empty() ? "/" : match[3].str();

  request.addHeader("Host", host);
  request.setPath(path);

  res = session->request(request);

  if (res.statusCode() != net::HttpResponse::OK) {
    return ac_id;
  }

  auto body = res.body();

  {
    auto i = find_ac_id(body);
    if (i.has_value()) {
      ac_id = i.value();
    }
  }

  return ac_id;
}

auto SrunClient::fetchIp() -> std::string {
  auto info = getInfo();
  if (info.errResponse().ecode() != 0) {
    throw SrunException(
        std::format("Fetch ip error: {}", info.errResponse().errMsg()));
  }

  return info.clientIp();
}

auto SrunClient::fetchUsername() -> std::string {
  auto info = getInfo();
  if (info.errResponse().ecode() != 0) {
    throw SrunException(
        std::format("Fetch username error: {}", info.errResponse().errMsg()));
  }

  return info.username();
}

auto SrunClient::checkOnline() -> bool {
  try {
    auto request = net::HttpRequest{};
    auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    request.addQuery("_", std::to_string(unix_time));

    auto&& response = api(INFO_PATH, request);

    if (response.statusCode() != net::HttpResponse::OK) {
      std::cerr << "check online error: " << response.statusMessage()
                << "\n";  // TODO(franzero): comment this
      return false;
    }

    auto info = InfoResponse{response.body()};
    return info.ok();
  } catch (const asio::system_error& e) {
    throw SrunException(std::format("Network error: {}", e.what()));
  }

  return false;
}

auto SrunClient::getInfo() -> InfoResponse {
  auto request = net::HttpRequest{};
  auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  request.addQuery("_", std::to_string(unix_time));

  auto&& response = api(INFO_PATH, request);

  if (response.statusCode() != net::HttpResponse::OK) {
    throw SrunHttpException(
        response.statusCode(),
        std::format("{} in getInfo", response.statusMessage()));
  }

  return InfoResponse{response.body()};
}

auto SrunClient::getChallenge() -> ChallengeResponse {
  if (_ip.empty()) {
    throw SrunException("Get challenge error: no ip");
  }

  if (_username.empty()) {
    throw SrunException("Get challenge error: no username");
  }

  auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

  auto request = net::HttpRequest{};
  request.addQuery("ip", _ip);
  request.addQuery("username", _username);
  request.addQuery("_", std::to_string(unix_time));

  auto&& response = api(CHALLENGE_PATH, request);
  if (response.statusCode() != net::HttpResponse::OK) {
    throw SrunHttpException(
        response.statusCode(),
        std::format("{} in getChallenge", response.statusMessage()));
  }

  return ChallengeResponse{response.body()};
}

auto SrunClient::login() -> void {
  if (_auto_ac_id) {
    _ac_id = fetchAcId();
  }

  if (_auto_ip) {
    _ip = fetchIp();
  }

  if (_ip.empty()) {
    throw SrunException("Login error: no ip");
  }

  if (_username.empty()) {
    throw SrunException("Login error: no username");
  }

  auto challenge = getChallenge();

  if (!challenge.ok()) {
    throw SrunException("Login error: " + challenge.errResponse().errMsg());
  }

  auto token = challenge.challenge();

  auto param_i = paramI(_username, _password, _ip, _ac_id, token);
  auto hmd5 = util::md5(token, _password);

  auto str = token + _username;
  str += token + hmd5;
  str += token + std::to_string(_ac_id);
  str += token + _ip;
  str += token + std::to_string(_n);
  str += token + std::to_string(_type);
  str += token + param_i;
  auto sha1 = util::sha1(str);

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
  auto&& response = api(AUTH_PATH, request);
  request.setPath(AUTH_PATH);

  if (response.statusCode() != net::HttpResponse::OK) {
    throw SrunHttpException(
        response.statusCode(),
        std::format("{} in login", response.statusMessage()));
  }

  auto login_response = LoginResponse{response.body()};
  if (!login_response.ok()) {
    throw SrunException("Login error: " +
                        login_response.errResponse().errMsg());
  }

  _access_token = login_response.accessToken();
}

auto SrunClient::logout() -> void {
  if (_ip.empty()) {
    _ip = fetchIp();
  }

  if (_username.empty()) {
    _username = fetchUsername();
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

  auto&& response = api(AUTH_PATH, request);
  if (response.statusCode() != net::HttpResponse::OK) {
    throw SrunHttpException(
        response.statusCode(),
        std::format("{} in logout", response.statusMessage()));
  }

  auto err_response = ErrResponse{response.body()};

  if (!err_response.ok() &&
      (err_response.errorMsg() != "You are not online.")) {
    throw SrunException("Logout error: " + err_response.errMsg());
  }
}

auto SrunClient::get(std::string_view path, net::HttpRequest request)
    -> net::HttpResponse {
#ifndef SRUN_SSL_ENABLED
  if (_ssl) {
    throw SrunSSLDisabledException{};
  }
#endif

  request.setMethod(net::HttpRequest::Method::GET);
  request.addHeader("Host", _host);
  request.setVersion(net::HttpRequest::Version::HTTP_1_1);
  request.setPath(path);

  auto session = newHttpClient();
  session->connect(_host, _port);
  return session->request(request);
}

auto SrunClient::api(std::string_view path, net::HttpRequest request)
    -> net::HttpResponse {
  request.addQuery("callback", "null");

  auto&& res = get(path, request);

  // remove "null" and "(" and ")"
  if (5 < res.body().size() &&
      (res.body().substr(0, 5) == "null(" && res.body().back() == ')')) {
    res.setBody(res.body().substr(5, res.body().size() - 6));
  }

  return res;
}
auto SrunClient::newHttpClient() -> std::shared_ptr<net::HttpSession> {
  auto session = std::make_shared<net::HttpSession>();

  if (_ssl) {
#ifndef SRUN_SSL_ENABLED
    throw SrunSSLDisabledException{};
#else
    session->setConnectCallback(
        [this](const std::shared_ptr<net::Session>& session) {
          session->socket().handshake(asio::ssl::stream_base::client);
        });
#endif
  }
  return session;
}

auto SrunClient::paramI(std::string_view username, std::string_view password,
                        std::string_view ip, int ac_id, std::string_view token)
    -> std::string {
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
         util::base64Encode(encode::encode(token, info),
                            "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/"
                            "3dlbfKwv6xztjI7DeBE45QA");
}

}  // namespace srun
