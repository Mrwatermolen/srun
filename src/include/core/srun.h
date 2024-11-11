#ifndef __SRUN_CORE_SRUN_H__
#define __SRUN_CORE_SRUN_H__

#include <string_view>

#include "core/common.h"
#include "net/http_request.h"
#include "net/http_response.h"
#include "net/http_session.h"

namespace srun {

class SRunClient {
 public:
  static constexpr std::string_view CHALLENGE_PATH = "/cgi-bin/get_challenge";
  static constexpr std::string_view INFO_PATH = "/cgi-bin/rad_user_info";
  static constexpr std::string_view AUTH_PATH = "/cgi-bin/srun_portal";

  static constexpr std::string_view DEFAULT_OS = "Linux";
  static constexpr std::string_view DEFAULT_OS_NAME = "Linux";

 public:
  SRunClient() = default;

  auto init(std::string_view config_path) -> void;

  auto init(std::string_view host, std::string_view port,
            std::string_view username, std::string_view password,
            bool ssl = false) -> void;

  auto ssl() const { return _ssl; }

  auto needAcId() const { return _need_ac_id; }

  auto needIp() const { return _need_ip; }

  auto host() const { return _host; }

  auto port() { return _port; }

  auto username() const { return _username; }

  auto setUsername(std::string_view username) -> void { _username = username; }

  auto password() const { return _password; }

  auto setPassword(std::string_view password) -> void { _password = password; }

  auto ip() const { return _ip; }

  auto setIp(std::string_view ip) -> void {
    _need_ip = false;
    _ip = ip;
  }

  auto acId() const { return _ac_id; }

  auto setAcId(std::size_t ac_id) -> void {
    _need_ac_id = false;
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

  auto fetchAcId() -> int;

  auto fetchIp() -> std::string;

  auto checkOnline() -> bool;

  auto getInfo() -> InfoResponse;

  auto getChallenge() -> ChallengeResponse;

  auto login() -> void;

  auto logout() -> void;

  auto api(std::string_view path,
           net::HttpRequest request) -> net::HttpResponse;

 private:
  auto newHttpClient() -> std::shared_ptr<net::HttpSession>;

  auto paramI(std::string_view username, std::string_view password,
              std::string_view ip, int ac_id,
              std::string_view token) -> std::string;

 private:
  asio::io_context _io_context;

  bool _ssl{false};
  bool _need_ac_id{true};
  bool _need_ip{true};

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
};

}  // namespace srun

#endif  // __SRUN_CORE_SRUN_H__
