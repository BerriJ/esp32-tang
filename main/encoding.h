#ifndef ENCODING_H
#define ENCODING_H

#include <cstdlib>
#include <cstring>
#include <mbedtls/base64.h>

static bool b64url_encode_buf(const uint8_t *data, size_t data_len,
                              char *out_buf, size_t out_max_len) {
  size_t b64_len = 0;
  int ret = mbedtls_base64_encode((unsigned char *)out_buf, out_max_len,
                                  &b64_len, data, data_len);
  if (ret != 0)
    return false;

  // Standard base64 → URL-safe: + → -, / → _, strip =
  for (size_t i = 0; i < b64_len; i++) {
    if (out_buf[i] == '+')
      out_buf[i] = '-';
    else if (out_buf[i] == '/')
      out_buf[i] = '_';
  }
  while (b64_len > 0 && out_buf[b64_len - 1] == '=')
    b64_len--;

  out_buf[b64_len] = '\0';
  return (b64_len < out_max_len);
}

static bool b64url_decode_buf(const char *in_str, uint8_t *out_buf,
                              size_t expected_len) {
  if (!in_str || !out_buf)
    return false;

  size_t in_len = strlen(in_str);
  size_t padded_len = in_len + (4 - in_len % 4) % 4;
  char *std_b64 = (char *)malloc(padded_len + 1);
  if (!std_b64)
    return false;

  // URL-safe → standard base64: - → +, _ → /
  for (size_t i = 0; i < in_len; i++) {
    if (in_str[i] == '-')
      std_b64[i] = '+';
    else if (in_str[i] == '_')
      std_b64[i] = '/';
    else
      std_b64[i] = in_str[i];
  }
  for (size_t i = in_len; i < padded_len; i++)
    std_b64[i] = '=';
  std_b64[padded_len] = '\0';

  size_t out_len = 0;
  int ret = mbedtls_base64_decode(out_buf, expected_len, &out_len,
                                  (const unsigned char *)std_b64, padded_len);
  free(std_b64);

  return (ret == 0 && out_len == expected_len);
}

#endif // ENCODING_H