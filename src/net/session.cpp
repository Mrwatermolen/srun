#include <iostream>

#include "net/buffer.h"
#include "net/session.h"

namespace srun::net {

auto Session::disconnect() -> void {}

auto Session::setConnectCallback(
    std::function<void(std::shared_ptr<Session>)> callback) -> void {
  _connect_callback = std::move(callback);
}

auto Session::setDisconnectCallback(
    std::function<void(std::shared_ptr<Session>)> callback) -> void {
  _disconnect_callback = std::move(callback);
}

auto Session::connect(std::string_view host, std::string_view service) -> void {
  auto self = shared_from_this();
  auto resolver = asio::ip::tcp::resolver{_io_context};
  auto query = asio::ip::tcp::resolver::query{host.data(), service.data()};

  auto endpoints = resolver.resolve(query);

#if SRUN_SSL_ENABLED
  auto &&socket = this->socket().lowest_layer();
#else
  auto &&socket = this->socket();
#endif

  socket.connect(*endpoints.begin());
  _connect_callback(shared_from_this());
}

auto Session::readSome() -> Buffer & {
  if (_read_buffer.empty()) {
    _read_buffer.resize(Buffer::DEFAULT_SIZE);
  }

  try {
    auto len = socket().read_some(
        asio::buffer(_read_buffer.writeBegin(), _read_buffer.writeableBytes()));
    _read_buffer.hasWritten(len);
    return _read_buffer;
  } catch (const asio::system_error &e) {
    if (e.code() != asio::error::eof) {
      std::cerr << "read error: " << e.what() << "\n";
    }

    throw e;
  }
}

auto Session::send(const Buffer &buffer) -> void {
  _write_buffer.append(buffer.readBegin(), buffer.readableBytes());
  try {
    while (_write_buffer.readableBytes() > 0) {
      auto len = socket().write_some(asio::buffer(
          _write_buffer.readBegin(), _write_buffer.readableBytes()));
      _write_buffer.retrieve(len);
    }
  } catch (const asio::system_error &e) {
    if (e.code() != asio::error::eof) {
      std::cerr << "send error: " << e.what() << "\n";
    }

    throw e;
  }
}

}  // namespace srun::net
