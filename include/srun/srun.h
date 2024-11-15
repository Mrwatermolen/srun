#ifndef __SRUN_CORE_SRUN_H__
#define __SRUN_CORE_SRUN_H__

#include <srun/common.h>

#include <memory>
#include <string>
#include <string_view>

namespace srun {

namespace net {

class HttpRequest;
class HttpResponse;
class HttpSession;

}  // namespace net

class SrunClient {
 public:
  static constexpr std::string_view CHALLENGE_PATH = "/cgi-bin/get_challenge";
  static constexpr std::string_view INFO_PATH = "/cgi-bin/rad_user_info";
  static constexpr std::string_view AUTH_PATH = "/cgi-bin/srun_portal";

  static constexpr std::string_view DEFAULT_OS = "Linux";
  static constexpr std::string_view DEFAULT_OS_NAME = "Linux";

 public:
  auto init(std::string_view config_path) -> void;

  auto ssl() const { return _ssl; }

  auto setSsl(bool ssl) -> void { _ssl = ssl; }

  auto autoAcId() const { return _auto_ac_id; }

  auto setAutoAcId(bool auto_ac_id) -> void { _auto_ac_id = auto_ac_id; }

  auto autoIp() const { return _auto_ip; }

  auto setAutoIp(bool auto_ip) -> void { _auto_ip = auto_ip; }

  auto host() const { return _host; }

  auto setHost(std::string_view host) -> void { _host = host; }

  auto port() { return _port; }

  auto setPort(std::string_view port) -> void { _port = port; }

  auto protocol() const { return _ssl ? "https" : "http"; }

  auto username() const { return _username; }

  auto setUsername(std::string_view username) -> void { _username = username; }

  auto password() const { return _password; }

  auto setPassword(std::string_view password) -> void { _password = password; }

  auto ip() const { return _ip; }

  auto setIp(std::string_view ip) -> void {
    _auto_ip = false;
    _ip = ip;
  }

  auto acId() const { return _ac_id; }

  auto setAcId(std::size_t ac_id) -> void {
    _auto_ac_id = false;
    _ac_id = ac_id;
  }

  auto n() const { return _n; }

  auto setN(std::size_t n) -> void { _n = n; }

  auto type() const { return _type; }

  auto setType(std::size_t type) -> void { _type = type; }

  auto os() const { return _os; }

  auto setOs(std::string_view os) -> void { _os = os; }

  auto osName() const { return _os_name; }

  auto setOsName(std::string_view os_name) -> void { _os_name = os_name; }

  auto doubleStack() const { return _double_stack; }

  auto setDoubleStack(int double_stack) -> void {
    _double_stack = double_stack;
  }

  auto accessToken() const { return _access_token; }

  auto setAccessToken(std::string_view access_token) -> void {
    _access_token = access_token;
  }

  auto fetchAcId() -> int;

  auto fetchIp() -> std::string;

  auto fetchUsername() -> std::string;

  auto checkOnline() -> bool;

  auto getInfo() -> InfoResponse;

  auto getChallenge() -> ChallengeResponse;

  auto login() -> void;

  auto logout() -> void;

  auto get(std::string_view path, net::HttpRequest request)
      -> net::HttpResponse;

  auto api(std::string_view path, net::HttpRequest request)
      -> net::HttpResponse;

 private:
  auto newHttpClient() -> std::shared_ptr<net::HttpSession>;

  auto paramI(std::string_view username, std::string_view password,
              std::string_view ip, int ac_id, std::string_view token)
      -> std::string;

 private:
  bool _ssl{false};
  bool _auto_ac_id{true};
  bool _auto_ip{true};

  std::string _host;
  std::string _port;

  std::string _username;
  std::string _password;

  std::string _ip;
  int _ac_id;
  int _n{200};
  int _type{1};
  std::string _os{DEFAULT_OS};
  std::string _os_name{DEFAULT_OS_NAME};
  int _double_stack{0};

  std::string _access_token;
};

}  // namespace srun

#endif  // __SRUN_CORE_SRUN_H__
