#include "core/srun.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>

#include "core/common.h"
#include "core/encode.h"
#include "core/util.h"
#include "net/http_request.h"
#include "net/http_response.h"

namespace srun {

auto SRunClient::init(std::string_view config_path) -> void {
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
  } catch (const std::out_of_range& e) {
    throw std::runtime_error(
        std::string(
            "SRunClient init error: missing required field in config. ") +
        e.what());
  }

  if (json.contains("ip")) {
    _need_ip = false;
    _ip = json["ip"];
  }

  if (json.contains("ac_id")) {
    _need_ac_id = false;
    _ac_id = json["ac_id"];
  }

  if (json.contains("os")) {
    _os = json["os"];
  }

  if (json.contains("os_name")) {
    _os_name = json["os_name"];
  }
}

auto SRunClient::init(std::string_view host, std::string_view port,
                      std::string_view username, std::string_view password,
                      bool ssl) -> void {
  _host = host;
  _port = port;
  _username = username;
  _password = password;
  _ssl = ssl;

  if (_ssl) {
#ifndef SRUN_SSL_ENABLED
    throw std::runtime_error("SRunClient init error: SSL don't support.");
#endif
  }
}

auto SRunClient::fetchAcId() -> int {
  int ac_id = 1;  // default 1
  auto session = newHttpClient();
  auto request = net::HttpRequest{};
  request.setMethod(srun::net::HttpRequest::Method::GET);
  request.setVersion(srun::net::HttpRequest::Version::HTTP_1_1);
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

auto SRunClient::fetchIp() -> std::string {
  auto info = getInfo();
  if (info.errResponse().ecode() != 0) {
    throw std::runtime_error("fetch ip error: " + info.errResponse().errMsg());
  }

  return info.clientIp();
}

auto SRunClient::checkOnline() -> bool {
  try {
    auto request = net::HttpRequest{};
    auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    request.addQuery("_", std::to_string(unix_time));

    auto&& response = api(INFO_PATH, request);

    if (response.statusCode() != net::HttpResponse::OK) {
      std::cerr << "check online error: " << response.statusMessage() << "\n";
      return false;
    }

    auto info = InfoResponse{response.body()};
    return info.ok();
  } catch (const asio::system_error& e) {
    std::cerr << "check online error: " << e.what() << "\n";
  }

  return false;
}

auto SRunClient::getInfo() -> InfoResponse {
  auto request = net::HttpRequest{};
  auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  request.addQuery("_", std::to_string(unix_time));

  auto&& response = api(INFO_PATH, request);

  if (response.statusCode() != net::HttpResponse::OK) {
    std::cerr << "check online error: " << response.statusMessage() << "\n";
    throw std::runtime_error("get info error");
  }

  return InfoResponse{response.body()};
}

auto SRunClient::getChallenge() -> ChallengeResponse {
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

  auto&& response = api(CHALLENGE_PATH, request);
  if (response.statusCode() != net::HttpResponse::OK) {
    throw std::runtime_error("get challenge error: " +
                             response.statusMessage());
  }

  return ChallengeResponse{response.body()};
}

auto SRunClient::login() -> void {
  if (_need_ac_id) {
    _ac_id = fetchAcId();
  }

  if (_need_ip) {
    _ip = fetchIp();
  }

  if (_ip.empty()) {
    throw std::runtime_error("login error: no ip");
  }

  auto challenge = getChallenge();

  if (!challenge.ok()) {
    throw std::runtime_error("login error: " +
                             challenge.errResponse().errMsg());
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
    throw std::runtime_error("login error: " + response.statusMessage());
  }

  auto err_response = ErrResponse{response.body()};
  if (!err_response.ok()) {
    throw std::runtime_error("login error: " + err_response.errMsg());
  }
}

auto SRunClient::logout() -> void {
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

  auto&& response = api(AUTH_PATH, request);
  if (response.statusCode() != net::HttpResponse::OK) {
    throw std::runtime_error("logout error: " + response.statusMessage());
  }

  auto err_response = ErrResponse{response.body()};

  if (!err_response.ok() &&
      (err_response.errorMsg() != "You are not online.")) {
    throw std::runtime_error("logout error: " + err_response.errMsg());
  }
}

auto SRunClient::api(std::string_view path,
                     net::HttpRequest request) -> net::HttpResponse {
  request.setMethod(net::HttpRequest::Method::GET);
  request.setPath(path);
  request.setVersion(net::HttpRequest::Version::HTTP_1_1);
  request.addHeader("Host", _host);
  request.addQuery("callback", "null");

  auto buffer = net::Buffer{};
  buffer.append(request.encodeBytes());

  auto session = newHttpClient();
  session->connect(_host, _port);
  auto&& res = session->request(request);
  // remove "null" and "(" and ")"
  if (5 < res.body().size() &&
      (res.body().substr(0, 5) == "null(" && res.body().back() == ')')) {
    res.setBody(res.body().substr(5, res.body().size() - 6));
  }

  return res;
}
auto SRunClient::newHttpClient() -> std::shared_ptr<net::HttpSession> {
  auto session = std::make_shared<net::HttpSession>(_io_context);
  if (_ssl) {
#ifndef SRUN_SSL_ENABLED
    throw std::runtime_error("new https session error: SSL don't support.");
#else
    session->setConnectCallback(
        [this](const std::shared_ptr<net::Session>& session) {
          session->socket().handshake(asio::ssl::stream_base::client);
        });
#endif
  }
  return session;
}

auto SRunClient::paramI(std::string_view username, std::string_view password,
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
         util::base64Encode(encode::encode(token, info),
                            "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/"
                            "3dlbfKwv6xztjI7DeBE45QA");
}

}  // namespace srun
