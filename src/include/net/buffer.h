#ifndef __SRUN_NET_BUFFER_H__
#define __SRUN_NET_BUFFER_H__

#include <cassert>
#include <cstring>
#include <vector>
#include <string>

namespace srun::net {

class Buffer {
 public:
  static constexpr std::size_t DEFAULT_SIZE = 1024;

  auto capacity() const { return _buffer.size(); }

  auto empty() const { return _writer_pos == _reader_pos; }

  auto full() const { return _writer_pos == _buffer.size(); }

  auto writeableBytes() const { return _buffer.size() - _writer_pos; }

  auto readableBytes() const { return _writer_pos - _reader_pos; }

  auto writeBegin() { return _buffer.data() + _writer_pos; }

  auto writeEnd() { return _buffer.data() + _buffer.size(); }

  auto readBegin() { return _buffer.data() + _reader_pos; }

  auto readEnd() { return _buffer.data() + _writer_pos; }

  auto readBegin() const { return _buffer.data() + _reader_pos; }

  auto readEnd() const { return _buffer.data() + _writer_pos; }

  auto hasWritten(std::size_t len) {
    _writer_pos += len;
    return _writer_pos;
  }

  auto append(const char *data, std::size_t len) {
    if (writeableBytes() < len) {
      auto new_size = std::max(_buffer.size() * 2, _buffer.size() + len);
      _buffer.resize(new_size);
    }

    std::copy(data, data + len, writeBegin());
    _writer_pos += len;
  }

  auto append(std::string_view data) { append(data.data(), data.size()); }

  auto append(const char *data) { append(data, std::strlen(data)); }

  auto append(char data) { append(&data, 1); }

  auto retrieve(std::size_t len) {
    if (readableBytes() <= len) {
      retrieveAll();
      return;
    }

    _reader_pos += len;
  }

  auto retrieveUntil(const char *end) {
    assert(readBegin() <= end);
    retrieve(end - readBegin());
  }

  auto retrieveAllAsString() {
    auto str = std::string{readBegin(), readableBytes()};
    retrieveAll();
    return str;
  }

  auto resize(std::size_t len) -> void {
    if (empty()) {
      retrieveAll();
      _buffer.resize(len);
      return;
    }

    if (len <= writeableBytes()) {
      return;
    }

    _buffer.resize(_buffer.size() + len);
  }

 private:
  auto retrieveAll() -> void {
    _reader_pos = 0;
    _writer_pos = 0;
  }

 private:
  std::size_t _writer_pos{};
  std::size_t _reader_pos{};
  std::vector<char> _buffer = std::vector<char>(DEFAULT_SIZE, 0);
};

}  // namespace srun::net

#endif  // __SRUN_NET_BUFFER_H__
