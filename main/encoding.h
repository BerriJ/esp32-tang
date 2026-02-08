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
    size_t output_len = 0;
    mbedtls_base64_encode(nullptr, 0, &output_len, data, len);

    uint8_t *buffer = new uint8_t[output_len + 1];
    if (mbedtls_base64_encode(buffer, output_len, &output_len, data, len) != 0)
    {
      delete[] buffer;
      return String();
    }
    buffer[output_len] = '\0';

    String encoded = String((char *)buffer);
    delete[] buffer;

    // Convert to URL-safe
    encoded.replace('+', '-');
    encoded.replace('/', '_');

    // Remove padding
    int padIndex = encoded.indexOf('=');
    if (padIndex != -1)
    {
      encoded.remove(padIndex);
    }

    return encoded;
  }

  static int decode(const String &b64_url, uint8_t *output, int max_len)
  {
    String b64 = b64_url;
    b64.replace('-', '+');
    b64.replace('_', '/');

    // Add padding
    while (b64.length() % 4)
    {
      b64 += "=";
    }

    size_t decoded_len = 0;
    int ret = mbedtls_base64_decode(output, max_len, &decoded_len,
                                    (const uint8_t *)b64.c_str(), b64.length());

    return (ret == 0) ? decoded_len : -1;
  }
};

#if defined(DEBUG_SERIAL) && DEBUG_SERIAL > 0
static void print_hex(const uint8_t *data, int len)
{
  for (int i = 0; i < len; ++i)
  {
    if (data[i] < 0x10)
      Serial.print("0");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}
#else
static void print_hex(const uint8_t *data, int len) {}
#endif

#endif // ENCODING_H
