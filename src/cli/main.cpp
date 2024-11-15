#include <chrono>
#include <exception>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <thread>

#include "argparse/argparse.hpp"
#include "srun/exception.h"
#include "srun/srun.h"

static auto srun_client = srun::SrunClient{};

void login(const argparse::ArgumentParser & /*srun_cli*/);

void logout(const argparse::ArgumentParser & /*srun_cli*/);

void info(const argparse::ArgumentParser & /*srun_cli*/);

int main(int argc, char *argv[]) {
  auto srun_cli = argparse::ArgumentParser("srun_cli");

  srun_cli.add_argument("--config")
      .help("config file path")
      .default_value(std::string(""));

  srun_cli.add_argument("--protocol")
      .help("protocol: http or https")
      .default_value(std::string("http"));
  srun_cli.add_argument("--host")
      .help("host: srun authentication host")
      .default_value(std::string(""));
  srun_cli.add_argument("--port")
      .help("port: authentication service port")
      .default_value(std::string("80"));
  srun_cli.add_argument("--username")
      .help("username")
      .default_value(std::string(""));
  srun_cli.add_argument("--password")
      .help("password")
      .default_value(std::string(""));
  srun_cli.add_argument("--ip")
      .help("ip: client ip. empty for auto fetch.")
      .default_value(std::string(""));
  srun_cli.add_argument("--ac_id")
      .help("ac_id")
      .default_value(1)
      .scan<'i', int>();
  srun_cli.add_argument("--os")
      .help("os: client os")
      .default_value(std::string("Linux"));
  srun_cli.add_argument("--os_name")
      .help("os_name: client os name")
      .default_value(std::string("Linux"));

  srun_cli.add_argument("--action")
      .help("action: 0 (login), 1 (logout), 2 (info). default 0")
      .default_value(0)
      .scan<'i', int>();

  srun_cli.add_argument("--retry")
      .help("retry times.")
      .default_value(4)
      .scan<'i', int>();

  try {
    srun_cli.parse_args(argc, argv);
  } catch (const std::runtime_error &err) {
    std::cerr << err.what() << '\n';
    std::cerr << srun_cli;
    return 1;
  }

  auto action_id = srun_cli.get<int>("--action");
  auto retry_times = srun_cli.get<int>("--retry");
  retry_times = (retry_times <= 0) ? 1 : retry_times;
  auto do_action = [&retry_times](auto &&action_func) {
    while (0 < retry_times) {
      try {
        action_func();
        break;
      } catch (const srun::SrunSSLDisabledException) {
        std::cerr << "Expect SSL/TLS support, but not enabled.\n";
        std::exit(1);
      } catch (const srun::SrunException &err) {
        std::cerr << "Error: " << err.what() << '\n';
        std::this_thread::sleep_for(std::chrono::seconds(1));
        --retry_times;
      } catch (const std::exception &err) {
        std::cerr << "Unexpected error: " << err.what() << '\n';
        std::exit(1);
      }
    }
  };

  if (action_id == 0) {
    if (!srun_cli.is_used("--config") &&
        (!srun_cli.is_used("--host") || !srun_cli.is_used("--username") ||
         !srun_cli.is_used("--password"))) {
      std::cerr << "Login requires --config or basic auth info including "
                   "--host, --username, --password\n";
      return 1;
    }

    do_action([&srun_cli]() { login(srun_cli); });
  }

  if (action_id == 1) {
    try {
      do_action([&srun_cli]() { logout(srun_cli); });
    } catch (const std::exception &e) {
      std::cerr << "Error: " << e.what() << '\n';
      return 1;
    }
  }

  if (action_id == 2) {
    do_action([&srun_cli]() { info(srun_cli); });
  }

  if (0 == retry_times) {
    std::cerr << "retry times exhausted.\n";
  } else {
    std::cout << "success.\n";
  }

  return 0;
}

auto args(const argparse::ArgumentParser &srun_cli) -> void {
  std::string used_args;
  if (srun_cli.is_used("--protocol")) {
    auto protocol = srun_cli.get<std::string>("--protocol");
    srun_client.setSsl(protocol == "https");
    used_args += std::format("protocol {} ", protocol);
  }

  if (srun_cli.is_used("--host")) {
    auto host = srun_cli.get<std::string>("--host");
    srun_client.setHost(host);
    used_args += std::format("host {} ", host);
  }

  if (srun_cli.is_used("--port")) {
    auto port = srun_cli.get<std::string>("--port");
    srun_client.setPort(port);
    used_args += std::format("port {} ", port);
  }

  if (srun_cli.is_used("--username")) {
    auto username = srun_cli.get<std::string>("--username");
    srun_client.setUsername(username);
    used_args += std::format("username {} ", username);
  }

  if (srun_cli.is_used("--password")) {
    auto password = srun_cli.get<std::string>("--password");
    srun_client.setPassword(password);
    used_args += std::format("password {} ", password);
  }

  if (srun_cli.is_used("--ip")) {
    auto ip = srun_cli.get<std::string>("--ip");
    srun_client.setIp(ip);
    used_args += std::format("ip {} ", ip);
  }

  if (srun_cli.is_used("--ac_id")) {
    auto ac_id = srun_cli.get<int>("--ac_id");
    srun_client.setAcId(ac_id);
    used_args += std::format("ac_id {} ", ac_id);
  }

  if (srun_cli.is_used("--os")) {
    auto os = srun_cli.get<std::string>("--os");
    srun_client.setOs(os);
    used_args += std::format("os {} ", os);
  }

  if (srun_cli.is_used("--os_name")) {
    auto os_name = srun_cli.get<std::string>("--os_name");
    srun_client.setOsName(os_name);
    used_args += std::format("os_name {} ", os_name);
  }

  if (!used_args.empty()) {
    std::cout << std::format("Using args: {}\n", used_args);
  }
}

auto login(const argparse::ArgumentParser &srun_cli) -> void {
  std::cout << "login...\n";

  bool ok_config_file = srun_cli.is_used("--config");

  if (ok_config_file) {
    try {
      auto config_file = srun_cli.get<std::string>("--config");
      std::cout << std::format("Using config file: {}\n", config_file);
      srun_client.init(config_file);

    } catch (const srun::SrunException &err) {
      std::cout << std::format("Error: {}\n", err.what());
      std::cout << std::format("Try to use basic auth info...\n");
      ok_config_file = false;
    }
  }

  if (!ok_config_file) {
    std::cout << "Using basic auth info...\n";
  }

  if (!srun_cli.is_used("host") && !ok_config_file) {
    throw std::runtime_error("host is required.");
  }

  args(srun_cli);

  if (srun_client.checkOnline()) {
    std::cout << "already online.\n";
    return;
  }

  srun_client.login();

  if (!srun_client.checkOnline()) {
    throw std::runtime_error("Login failed.\n");
  }

  std::cout << "login success.\n";
}

auto logout(const argparse::ArgumentParser &srun_cli) -> void {
  std::cout << "logout...\n";

  bool ok_config_file = srun_cli.is_used("--config");

  if (ok_config_file) {
    try {
      auto config_file = srun_cli.get<std::string>("--config");
      std::cout << std::format("Using config file: {}\n", config_file);
      srun_client.init(config_file);
    } catch (const srun::SrunException &e) {
      std::cout << std::format("Error: {}\n", e.what());
      std::cout << std::format("Try to use args...\n");
      ok_config_file = false;
    }
  }

  if (!srun_cli.is_used("host") && !ok_config_file) {
    throw std::runtime_error("host is required.");
  }

  args(srun_cli);

  if (!srun_client.checkOnline()) {
    std::cout << "not online.\n";
    return;
  }
  srun_client.logout();

  std::cout << "logout success.\n";
  if (srun_client.checkOnline()) {
    throw std::runtime_error("Still online. Logout failed.\n");
  }
}

auto info(const argparse::ArgumentParser &srun_cli) -> void {
  std::cout << "info...\n";
  bool ok_config_file = srun_cli.is_used("--config");
  if (ok_config_file) {
    try {
      auto config_file = srun_cli.get<std::string>("--config");
      std::cout << std::format("Using config file: {}\n", config_file);
      srun_client.init(config_file);
    } catch (const srun::SrunException &e) {
      std::cout << std::format("Error: {}\n", e.what());
      std::cout << std::format("Try to use args...\n");
      ok_config_file = false;
    }
  }

  if (!srun_cli.is_used("host") && !ok_config_file) {
    throw std::runtime_error("host is required.");
  }

  args(srun_cli);

  auto info = srun_client.getInfo();
  std::cout << info.toInfoString() << '\n';
}
