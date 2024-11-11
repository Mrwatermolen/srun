#ifndef __SRUN_UTIL_H__
#define __SRUN_UTIL_H__

// #include <openssl/hmac.h>
// #include <openssl/sha.h>

// #include <iomanip>
// #include <sstream>
#include <string>
#include <string_view>

#include "hash_library/hmac.h"
#include "hash_library/md5.h"
#include "hash_library/sha1.h"

namespace srun::util {

inline auto md5(std::string_view key, std::string_view data) -> std::string {
  // unsigned char *result;
  // static const size_t hash_len = EVP_MD_size(EVP_md5());
  // result = static_cast<unsigned char *>(malloc(hash_len));

  // HMAC(EVP_md5(), key.data(), key.length(),
  //      reinterpret_cast<const unsigned char *>(data.data()), data.length(),
  //      result, nullptr);

  // std::ostringstream oss;
  // for (size_t i = 0; i < hash_len; ++i) {
  //   oss << std::hex << std::setw(2) << std::setfill('0')
  //       << static_cast<int>(result[i]);
  // }

  // free(result);
  // return oss.str();

  return hash::hmac<hash::MD5>(key.data(), key.size(), data.data(),
                               data.size());
}

inline auto sha1(std::string_view data) -> std::string {
  // unsigned char hash[SHA_DIGEST_LENGTH];
  // SHA1(reinterpret_cast<const unsigned char *>(data.data()), data.size(),
  // hash);

  // std::ostringstream oss;
  // for (unsigned char i : hash) {
  //   oss << std::hex << std::setw(2) << std::setfill('0') <<
  //   static_cast<int>(i);
  // }

  // return oss.str();

  return hash::SHA1{}(data.data());
}

inline auto base64Encode(std::string_view input,
                         std::string_view base64_chars) -> std::string {
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
