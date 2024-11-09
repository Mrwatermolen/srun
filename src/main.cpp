#include "srun.hpp"

int main() {
  srun::SRunClient client("config.json");

  int retry_times = 4;
  while (!client.checkOnline() && 0 < retry_times) {
    --retry_times;
    try {
      client.login();
      std::cout << "login success\n";
      return 0;
    } catch (const std::exception &e) {
      std::cerr << "login failed: " << e.what() << "\n";
    }
  }

  return retry_times <= 0 ? (1) : (0);
}
