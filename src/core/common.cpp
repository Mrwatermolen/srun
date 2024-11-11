#include "core/common.h"

#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>

namespace srun {

template <typename K, typename V>
static auto kvToStringJson(const K &key, const V &value) -> std::string {
  // can't handle chinese
  // if constexpr (std::is_arithmetic_v<V>) {
  //   return std::format("\"{}\":{}", key, value);
  // }

  // return std::format(R"("{}":"{}")", key, value);

  auto json = nlohmann::json{};
  json[key] = value;
  return json.dump().substr(1, json.dump().size() - 2);
}

ErrResponse::ErrResponse(std::string_view data) {
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

auto ErrResponse::errMsg() const -> std::string {
  std::string result = "{";
  result += kvToStringJson("error", _error) + ",";
  result += kvToStringJson("error_msg", _error_msg);
  result += "}";
  return result;
}

auto ErrResponse::toFormatString() const -> std::string {
  std::string result = "{";
  result += kvToStringJson("ecode", _ecode) + ",";
  result += kvToStringJson("error", _error) + ",";
  result += kvToStringJson("error_msg", _error_msg);
  result += "}";
  return result;
}

InfoResponse::InfoResponse(std::string_view data) {
  auto json = nlohmann::json::parse(data);
  try {
    _err_response = ErrResponse{data};
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
    std::string online_device_detail = json["online_device_detail"];
    auto online_device_detail_json =
        nlohmann::json::parse(online_device_detail);
    for (const auto &device : online_device_detail_json) {
      _online_devices.push_back(OnlineDevice{
          ._class_name = device["class_name"],
          ._ip = device["ip"],
          ._ip6 = device["ip6"],
          ._os_name = device["os_name"],
          ._rad_online_id = device["rad_online_id"],
      });
    }
    _products_id = json["products_id"];
    _products_name = json["products_name"];
    _remain_bytes = json["remain_bytes"];
    _remain_seconds = json["remain_seconds"];
    _sum_bytes = json["sum_bytes"];
    _sum_seconds = json["sum_seconds"];
    _user_balance = json["user_balance"];
    _user_charge = json["user_charge"];
    _user_mac = json["user_mac"];
    _username = json["user_name"];
    _wallet_balance = json["wallet_balance"];
  } catch (const std::exception &e) {
    std::cerr << "parse info response error: " << e.what() << "\n";
    return;
  }
}

auto InfoResponse::toFormatString() const -> std::string {
  std::string result = "{";
  result += R"("err_response":)";
  result += _err_response.toFormatString();
  if (!_err_response.ok()) {
    if (!_client_ip.empty()) {
      result += ",";
      result += kvToStringJson("client_ip", _client_ip);
    }
    result += "}";
    return result;
  }

  result += ",";
  result += kvToStringJson("client_ip", _client_ip) + ",";
  result += kvToStringJson("online_ip", _online_ip) + ",";
  result += kvToStringJson("add_time", _add_time) + ",";
  result += kvToStringJson("billing_name", _billing_name) + ",";
  result += kvToStringJson("bytes_in", _bytes_in) + ",";
  result += kvToStringJson("bytes_out", _bytes_out) + ",";
  result += kvToStringJson("keepalive_time", _keepalive_time) + ",";
  result += R"("online_devices":[)";
  for (const auto &device : _online_devices) {
    result += "{";
    result += kvToStringJson("class_name", device.className()) + ",";
    result += kvToStringJson("ipv4", device.ipv4()) + ",";
    result += kvToStringJson("ipv6", device.ipv6()) + ",";
    result += kvToStringJson("os_name", device._os_name) + ",";
    result += kvToStringJson("rad_online_id", device._rad_online_id);
    result += "},";
  }
  if (!_online_devices.empty()) {
    result.pop_back();
  }
  result += "],";
  result += kvToStringJson("products_id", _products_id) + ",";
  result += kvToStringJson("products_name", _products_name) + ",";
  result += kvToStringJson("remain_bytes", _remain_bytes) + ",";
  result += kvToStringJson("remain_seconds", _remain_seconds) + ",";
  result += kvToStringJson("sum_bytes", _sum_bytes) + ",";
  result += kvToStringJson("sum_seconds", _sum_seconds) + ",";
  result += kvToStringJson("user_balance", _user_balance) + ",";
  result += kvToStringJson("user_charge", _user_charge) + ",";
  result += kvToStringJson("user_mac", _user_mac) + ",";
  result += kvToStringJson("user_name", _username) + ",";
  result += kvToStringJson("wallet_balance", _wallet_balance);

  result += "}";
  return result;
}

auto InfoResponse::toInfoString() const -> std::string {
  // ALign and format the string
  std::stringstream ss;
  int precision = 2;
  int width = 25;
  ss << std::fixed << std::setprecision(precision);
  ss << "INFO:\n";

  if (!_err_response.ok()) {
    ss << std::left << std::setw(width)
       << "ERROR: " << _err_response.toFormatString() << "\n";
    ss << std::left << std::setw(width) << "CLIENT IP: " << _client_ip << "\n";
    ss << std::left << std::setw(width) << "ONLINE IP: " << _online_ip << "\n";

    return ss.str();
  }

  ss << std::left << std::setw(width) << "CLIENT IP: " << _client_ip << "\n";
  ss << std::left << std::setw(width) << "ONLINE IP: " << _online_ip << "\n";
  ss << std::left << std::setw(width) << "PRODUCTS ID: " << _products_id
     << "\n";
  ss << std::left << std::setw(width) << "PRODUCTS NAME: " << _products_name
     << "\n";
  ss << std::left << std::setw(width) << "BILLING NAME: " << _billing_name
     << "\n";
  ss << std::left << std::setw(width) << "USER NAME: " << _username << "\n";
  ss << std::left << std::setw(width) << "USER BALANCE: " << _user_balance
     << "\n";
  ss << std::left << std::setw(width) << "USER CHARGE: " << _user_charge
     << "\n";
  ss << std::left << std::setw(width) << "USER MAC: " << _user_mac << "\n";
  ss << std::left << std::setw(width) << "WALLET BALANCE: " << _wallet_balance
     << "\n";
  ss << std::left << std::setw(width)
     << "ADD TIME: " << (static_cast<double>(_add_time) / 86400 / 365)
     << " Years OR " << (static_cast<double>(_add_time) / 86400 / 30)
     << " Months OR " << (static_cast<double>(_add_time) / 86400) << " Days OR "
     << (static_cast<double>(_add_time) / 3600) << " Hours OR "
     << (static_cast<double>(_add_time) / 60) << " Minutes OR " << _add_time
     << " Seconds\n";
  ss << std::left << std::setw(width) << "KEEPALIVE TIME: "
     << (static_cast<double>(_keepalive_time) / 86400 / 365) << " Years OR "
     << (static_cast<double>(_keepalive_time) / 86400 / 30) << " Months OR "
     << (static_cast<double>(_keepalive_time) / 86400) << " Days OR "
     << (static_cast<double>(_keepalive_time) / 3600) << " Hours OR "
     << (static_cast<double>(_keepalive_time) / 60) << " Minutes OR "
     << _keepalive_time << " Seconds\n";
  ss << std::left << std::setw(width)
     << "SUM TIME: " << (static_cast<double>(_sum_seconds) / 86400 / 365)
     << " Years OR " << (static_cast<double>(_sum_seconds) / 86400 / 30)
     << " Months OR " << (static_cast<double>(_sum_seconds) / 86400)
     << " Days OR " << (static_cast<double>(_sum_seconds) / 3600)
     << " Hours OR " << (static_cast<double>(_sum_seconds) / 60)
     << " Minutes OR " << _sum_seconds << " Seconds\n";
  ss << std::left << std::setw(width) << "REMAIN SECONDS: "
     << (static_cast<double>(_remain_seconds) / 86400 / 365) << " Years OR "
     << (static_cast<double>(_remain_seconds) / 86400 / 30) << " Months OR "
     << (static_cast<double>(_remain_seconds) / 86400) << " Days OR "
     << (static_cast<double>(_remain_seconds) / 3600) << " Hours OR "
     << (static_cast<double>(_remain_seconds) / 60) << " Minutes OR "
     << _remain_seconds << " Seconds\n";
  ss << std::left << std::setw(width)
     << "BYTES IN: " << (static_cast<double>(_bytes_in) / 1024 / 1024 / 1024)
     << " GB OR " << (static_cast<double>(_bytes_in) / 1024 / 1024) << " MB OR "
     << (static_cast<double>(_bytes_in) / 1024) << " KB OR " << _bytes_in
     << " Bytes\n";
  ss << std::left << std::setw(width)
     << "BYTES OUT: " << (static_cast<double>(_bytes_out) / 1024 / 1024 / 1024)
     << " GB OR " << (static_cast<double>(_bytes_out) / 1024 / 1024)
     << " MB OR " << (static_cast<double>(_bytes_out) / 1024) << " KB OR "
     << _bytes_out << " Bytes\n";
  ss << std::left << std::setw(width) << "REMAIN BYTES: "
     << (static_cast<double>(_remain_bytes) / 1024 / 1024 / 1024) << " GB OR "
     << (static_cast<double>(_remain_bytes) / 1024 / 1024) << " MB OR "
     << (static_cast<double>(_remain_bytes) / 1024) << " KB OR "
     << _remain_bytes << " Bytes\n";
  ss << std::left << std::setw(width)
     << "SUM BYTES: " << (static_cast<double>(_sum_bytes) / 1024 / 1024 / 1024)
     << " GB OR " << (static_cast<double>(_sum_bytes) / 1024 / 1024)
     << " MB OR " << (static_cast<double>(_sum_bytes) / 1024) << " KB OR "
     << _sum_bytes << " Bytes\n";

  int i = 1;
  for (const auto &device : _online_devices) {
    ss << std::left << std::setw(width) << "DEVICE: " << i++ << "\n";
    ss << std::left << std::setw(width)
       << "DEVICE CLASS NAME: " << device.className() << "\n";
    ss << std::left << std::setw(width) << "DEVICE IPV4: " << device.ipv4()
       << "\n";
    ss << std::left << std::setw(width) << "DEVICE IPV6: " << device.ipv6()
       << "\n";
    ss << std::left << std::setw(width) << "DEVICE OS NAME: " << device.osName()
       << "\n";
    ss << std::left << std::setw(width)
       << "DEVICE RAD ONLINE ID: " << device.radOnlineId() << "\n";
  }

  return ss.str();
}

ChallengeResponse::ChallengeResponse(std::string_view data) {
  auto json = nlohmann::json::parse(data);

  try {
    _err_response = ErrResponse{data};

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

}  // namespace srun
