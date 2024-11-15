#ifndef __SRUN_UTIL_H__
#define __SRUN_UTIL_H__

#include <string>
#include <string_view>

#include "hash_library/hmac.h"
#include "hash_library/md5.h"
#include "hash_library/sha1.h"

namespace srun::util {

inline auto md5(std::string_view key, std::string_view data) -> std::string {
  return hash::hmac<hash::MD5>(key.data(), key.size(), data.data(),
                               data.size());
}

inline auto sha1(std::string_view data) -> std::string {
  return hash::SHA1{}(std::string{data});
}

inline auto base64Encode(std::string_view input, std::string_view base64_chars)
    -> std::string {
  std::string encoded;
  int val = 0;
  int valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
  }
  while ((encoded.size() % 4) != 0U) {
    encoded.push_back('=');
  }
  return encoded;
}

}  // namespace srun::util

#endif  // __SRUN_UTIL_H__
