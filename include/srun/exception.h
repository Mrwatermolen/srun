#ifndef __SRUN_EXCEPTION_H__
#define __SRUN_EXCEPTION_H__

#include <exception>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace srun {

struct SrunException : public std::exception {
  explicit SrunException(std::string msg) : _msg(std::move(msg)) {}

  explicit SrunException(const char* msg) : _msg(msg) {}

  explicit SrunException(std::string_view msg) : _msg(msg) {}

  const char* what() const noexcept override { return _msg.c_str(); }

 private:
  std::string _msg;
};

struct SrunSSLDisabledException : SrunException {
  SrunSSLDisabledException()
      : SrunException{"SSL/TLS don't support, please recompile with SSL/TLS."} {
  }
};

struct SrunHttpException : SrunException {
  SrunHttpException(int code, std::string_view msg)
      : SrunException{std::format("HTTP error: {} {}", code, msg)} {}
};

}  // namespace srun

#endif  // __SRUN_EXCEPTION_H__
