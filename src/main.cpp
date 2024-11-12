#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

#include "argparse/argparse.hpp"
#include "core/srun.h"

int main(int argc, char *argv[]) {
  auto srun_program = argparse::ArgumentParser("srun");

  srun_program.add_argument("--config")
      .help("config file path")
      .default_value(std::string(""));

  srun_program.add_argument("--protocol")
      .help("protocol: http or https")
      .default_value(std::string("http"));
  srun_program.add_argument("--host")
      .help("host: srun authentication host")
      .default_value(std::string(""));
  srun_program.add_argument("--port")
      .help("port: authentication service port")
      .default_value(std::string("80"));
  srun_program.add_argument("--username")
      .help("username")
      .default_value(std::string(""));
  srun_program.add_argument("--password")
      .help("password")
      .default_value(std::string(""));
  srun_program.add_argument("--ip")
      .help("ip: client ip. empty for auto fetch.")
      .default_value(std::string(""));
  srun_program.add_argument("--ac_id")
      .help("ac_id")
      .default_value(1)
      .scan<'i', int>();
  srun_program.add_argument("--os")
      .help("os: client os")
      .default_value(std::string("Linux"));
  srun_program.add_argument("--os_name")
      .help("os_name: client os name")
      .default_value(std::string("Linux"));

  srun_program.add_argument("--action")
      .help("action: 0 (login), 1 (logout), 2 (info). default 0")
      .default_value(0)
      .scan<'i', int>();

  srun_program.add_argument("--retry")
      .help("retry times.")
      .default_value(4)
      .scan<'i', int>();

  std::string config_file;
  std::string host;
  std::string username;
  std::string password;

  try {
    srun_program.parse_args(argc, argv);
    config_file = srun_program.get<std::string>("--config");
    host = srun_program.get<std::string>("--host");
    username = srun_program.get<std::string>("--username");
    password = srun_program.get<std::string>("--password");

    if (config_file.empty() &&
        (host.empty() || username.empty() || password.empty())) {
      throw std::runtime_error(
          "missing required field: --config or basic auth info including "
          "--host, --username, --password");
    }

  } catch (const std::runtime_error &err) {
    std::cerr << err.what() << '\n';
    std::cerr << srun_program;
    return 1;
  }

  srun::SRunClient client{};
  try {
    if (!config_file.empty()) {
      client.init(config_file);
    } else {
      auto protocol = srun_program.get<std::string>("--protocol");
      auto host = srun_program.get<std::string>("--host");
      auto port = srun_program.get<std::string>("--port");
      if (protocol == "https" && port == "80") {
        port = "443";
      }
      auto username = srun_program.get<std::string>("--username");
      auto password = srun_program.get<std::string>("--password");

      client.init(host, port, username, password, protocol == "https");

      if (srun_program.is_used("--ac_id")) {
        auto ac_id = srun_program.get<int>("--ac_id");
        client.setAcId(ac_id);
      }

      if (srun_program.is_used("--ip")) {
        auto ip = srun_program.get<std::string>("--ip");
        client.setIp(ip);
      }

      auto os = srun_program.get<std::string>("--os");
      client.setOs(os);
      auto os_name = srun_program.get<std::string>("--os_name");
      client.setOsName(os_name);
    }
  } catch (std::runtime_error &err) {
    std::cerr << err.what() << '\n';
    return 1;
  }

  auto action = srun_program.get<int>("--action");
  auto retry_times = srun_program.get<int>("--retry");
  if (retry_times < 0) {
    retry_times = 1;
  }

  while (0 < retry_times) {
    try {
      switch (action) {
        case 0: {
          std::cout << "login...\n";
          if (client.checkOnline()) {
            std::cout << "already online.\n";
            break;
          }

          client.login();
          break;
        }
        case 1: {
          std::cout << "logout...\n";
          if (!client.checkOnline()) {
            std::cout << "already offline.\n";
            break;
          }
          client.logout();
          break;
        }
        case 2: {
          std::cout << "info...\n";
          auto info = client.getInfo();
          std::cout << info.toInfoString() << '\n';
          break;
        }
        default:
          std::cout << "unknown action: " << action << '\n';
      }
      std::cout << "success.\n";
      break;
    } catch (const std::runtime_error &err) {
      --retry_times;
      std::cerr << err.what() << '\n';
      std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
  }

  if (0 == retry_times) {
    std::cerr << "retry times exhausted.\n";
  }

  return 0;
}
