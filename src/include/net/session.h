#ifndef __SRUN_NET_SESSION_H__
#define __SRUN_NET_SESSION_H__

#include <asio.hpp>

#ifdef SRUN_SSL_ENABLED
#include <asio/ssl.hpp>
#endif

#include "net/buffer.h"

namespace srun::net {

class Session : public std::enable_shared_from_this<Session> {
  inline static asio::io_context io_context;
#ifdef SRUN_SSL_ENABLED
  inline static asio::ssl::context ssl_context{asio::ssl::context::tlsv12};
#endif
 public:
  Session()
      :
#if SRUN_SSL_ENABLED
        _socket{_io_context, _ssl_context}
#else
        _socket{_io_context}
#endif
  {
  }

  virtual ~Session() = default;

  auto &socket() { return _socket; }

  auto &socket() const { return _socket; }

  auto &writeBuffer() { return _write_buffer; }

  auto &readBuffer() { return _read_buffer; }

  auto &writeBuffer() const { return _write_buffer; }

  auto &readBuffer() const { return _read_buffer; }

  auto setConnectCallback(
      std::function<void(std::shared_ptr<Session>)> callback) -> void;

  auto connect(std::string_view host, std::string_view service) -> void;

  auto readSome() -> Buffer &;

  auto send(const Buffer &buffer) -> void;

 private:
  asio::io_context &_io_context{io_context};
#if SRUN_SSL_ENABLED
  asio::ssl::context &_ssl_context{ssl_context};
  asio::ssl::stream<asio::ip::tcp::socket> _socket;
#else
  asio::ip::tcp::socket _socket;
#endif
  Buffer _read_buffer;
  Buffer _write_buffer;
  std::function<void(std::shared_ptr<Session>)> _connect_callback;
};

}  // namespace srun::net

#endif  // __SRUN_NET_SESSION_H__
