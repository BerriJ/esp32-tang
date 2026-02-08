#ifndef ENCODING_H
#define ENCODING_H

#include <Arduino.h>
#include <mbedtls/base64.h>

// --- Base64URL Encoding ---
class Base64URL
{
public:
  static String encode(const uint8_t *data, size_t len)
  {
    size_t olen = 0;
    mbedtls_base64_encode(nullptr, 0, &olen, data, len);

    char *buf = new char[olen + 1];
    mbedtls_base64_encode((uint8_t *)buf, olen, &olen, data, len);
    buf[olen] = '\0';

    String result(buf);
    delete[] buf;

    result.replace('+', '-');
    result.replace('/', '_');
    int pad = result.indexOf('=');
    if (pad != -1)
      result.remove(pad);

    return result;
  }

  static int decode(const String &b64_url, uint8_t *output, int max_len)
  {
    String b64 = b64_url;
    b64.replace('-', '+');
    b64.replace('_', '/');
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
