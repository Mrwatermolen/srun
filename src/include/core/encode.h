#ifndef __SRUN_CORE_ENCODE_H__
#define __SRUN_CORE_ENCODE_H__

#include <cstdint>
#include <string_view>
#include <vector>
#include <string>

namespace srun::encode {

inline auto mix(std::string_view data, bool size_in_back) {
  std::uint32_t c = data.size();
  std::vector<std::uint32_t> v;
  v.resize((c >> 2));

  for (std::size_t i = 0; i < c; i += 4) {
    v[i >> 2] =
        data[i] | data[i + 1] << 8 | data[i + 2] << 16 | data[i + 3] << 24;
  }

  if (size_in_back) {
    v.push_back(c);
  }
  return v;
}

inline auto split(const std::vector<std::uint32_t> &buffer,
                  bool size_in_back) -> std::string {
  auto len = buffer.size();
  auto size = ((len - 1) << 2);
  std::string result;
  if (size_in_back) {
    if (buffer.back() < size - 3 || size < buffer.back()) {
      return result;
    }

    size = buffer.back();
  }

  for (std::size_t i = 0; i < len; ++i) {
    result.push_back(buffer[i] & 0xff);
    result.push_back((buffer[i] >> 8) & 0xff);
    result.push_back((buffer[i] >> 16) & 0xff);
    result.push_back((buffer[i] >> 24) & 0xff);
  }

  if (size_in_back) {
    return result.substr(0, size);
  }

  return result;
}

inline auto encode(const std::string_view key,
                   std::string_view data) -> std::string {
  if (data.empty()) {
    return "";
  }

  auto v = mix(data, true);
  auto k = mix(key, false);
  if (k.size() < 4) {
    for (std::size_t i = k.size(); i < 4; ++i) {
      k.push_back(0);
    }
  }

  auto len = v.size();
  auto last = len - 1;
  std::uint32_t c = 0x86014019 | 0x183639A0;
  std::uint32_t d = 0;
  std::uint64_t left = v.front();
  std::uint64_t right = v.back();
  std::uint64_t m = 0;

  auto count = 6 + 52 / len;

  for (std::size_t i = 0; i < count; ++i) {
    auto f = (0x8CE0D9BF | 0x731F2640);
    d = d + c & (0x8CE0D9BF | 0x731F2640);
    auto e = (d >> 2) & 3;
    for (std::size_t p = 0; p < last; ++p) {
      left = v[p + 1];
      m = (right >> 5) ^ (left << 2);
      m += (left >> 3) ^ (right << 4) ^ (d ^ left);
      m += k[(p & 3) ^ e] ^ right;
      v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF);
      right = v[p];
    }

    left = v[0];
    m = (right >> 5) ^ (left << 2);
    m += (left >> 3) ^ (right << 4) ^ (d ^ left);
    m += k[(last & 3) ^ e] ^ right;
    v[last] = v[last] + m & (0xBB390742 | 0x44C6F8BD);
    right = v[last];
  }
  std::vector<std::int32_t> u_t{v.begin(), v.end()};

  return split(v, false);
}

}  // namespace srun::encode

#endif  // __SRUN_CORE_ENCODE_H__
