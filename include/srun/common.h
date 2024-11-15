#ifndef __SRUN_CORE_COMMON_H__
#define __SRUN_CORE_COMMON_H__

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace srun {

struct ErrResponse {
  static constexpr std::string_view OK_MSG = "ok";

  ErrResponse() = default;

  explicit ErrResponse(std::string_view data);

  auto ok() const { return _ecode == 0 && _error == OK_MSG; }

  auto errMsg() const -> std::string;

  auto ecode() const { return _ecode; }

  auto error() const { return _error; }

  auto errorMsg() const { return _error_msg; }

  auto toFormatString() const -> std::string;

  int _ecode{-1};
  std::string _error_msg;
  std::string _error;
};

struct InfoResponse {
  InfoResponse() = default;

  explicit InfoResponse(std::string_view data);

  auto ok() const { return _err_response.ok(); }

  auto errResponse() const { return _err_response; }

  auto onlineIp() const { return _online_ip; }

  auto clientIp() const { return _client_ip; }

  auto addTime() const { return _add_time; }

  auto billingName() const { return _billing_name; }

  auto bytesIn() const { return _bytes_in; }

  auto bytesOut() const { return _bytes_out; }

  auto keepAliveTime() const { return _keepalive_time; }

  auto onlineDevices() const { return _online_devices; }

  auto productId() const { return _products_id; }

  auto productName() const { return _products_name; }

  auto remainBytes() const { return _remain_bytes; }

  auto remainSeconds() const { return _remain_seconds; }

  auto sumBytes() const { return _sum_bytes; }

  auto sumSeconds() const { return _sum_seconds; }

  auto userBalance() const { return _user_balance; }

  auto userCharge() const { return _user_charge; }

  auto userMac() const { return _user_mac; }

  auto username() const { return _username; }

  auto walletBalance() const { return _wallet_balance; }

  auto toFormatString() const -> std::string;

  auto toInfoString() const -> std::string;

  struct OnlineDevice {
    auto className() const { return _class_name; }

    auto ipv4() const { return _ip; }

    auto ipv6() const { return _ip6; }

    auto osName() const { return _os_name; }

    auto radOnlineId() const { return _rad_online_id; }

    std::string _class_name;
    std::string _ip;
    std::string _ip6;
    std::string _os_name;
    std::string _rad_online_id;
  };

  ErrResponse _err_response;

  std::string _online_ip;

  std::string _client_ip;
  std::size_t _add_time;
  std::string _billing_name;
  std::size_t _bytes_in{};
  std::size_t _bytes_out{};
  std::size_t _keepalive_time{};
  std::vector<OnlineDevice> _online_devices;
  std::string _products_id;
  std::string _products_name;
  std::size_t _remain_bytes{};
  std::size_t _remain_seconds{};
  std::size_t _sum_bytes{};
  std::size_t _sum_seconds{};
  std::size_t _user_balance{};
  std::size_t _user_charge{};
  std::string _user_mac;
  std::string _username;
  std::size_t _wallet_balance{};
};

struct ChallengeResponse {
  ChallengeResponse() = default;

  explicit ChallengeResponse(std::string_view data);

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

struct LoginResponse {
  LoginResponse() = default;

  explicit LoginResponse(std::string_view data);

  auto ok() const { return _err_response.ok(); }

  auto errResponse() const { return _err_response; }

  auto accessToken() const { return _access_token; }

  ErrResponse _err_response;
  std::string _access_token;
};

}  // namespace srun

#endif  // __SRUN_CORE_COMMON_H__
