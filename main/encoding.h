#ifndef ENCODING_H
#define ENCODING_H

#include <string>
#include <cstring>
#include <mbedtls/base64.h>

// --- Base64URL Encoding ---
class Base64URL
{
public:
  static std::string encode(const uint8_t *data, size_t len)
  {
    size_t olen = 0;
    mbedtls_base64_encode(nullptr, 0, &olen, data, len);

    char *buf = new char[olen + 1];
    mbedtls_base64_encode((uint8_t *)buf, olen, &olen, data, len);
    buf[olen] = '\0';

    std::string result(buf);
    delete[] buf;

    // Replace + with -, / with _, and remove padding
    for (size_t i = 0; i < result.length(); i++)
    {
      if (result[i] == '+')
        result[i] = '-';
      else if (result[i] == '/')
        result[i] = '_';
    }

    size_t pad = result.find('=');
    if (pad != std::string::npos)
      result.erase(pad);

    return result;
  }

  static int decode(const std::string &b64_url, uint8_t *output, int max_len)
  {
    std::string b64 = b64_url;

    // Replace URL-safe characters back to standard base64
    for (size_t i = 0; i < b64.length(); i++)
    {
      if (b64[i] == '-')
        b64[i] = '+';
      else if (b64[i] == '_')
        b64[i] = '/';
    }

    // Add padding
    while (b64.length() % 4)
      b64 += '=';

    size_t len = 0;
    return (mbedtls_base64_decode(output, max_len, &len,
                                  (const uint8_t *)b64.c_str(), b64.length()) == 0)
               ? len
               : -1;
  }
};

#endif // ENCODING_H
