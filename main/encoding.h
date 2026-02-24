#ifndef ENCODING_H
#define ENCODING_H

#include "atca_helpers.h"
#include <cstring>
#include <mbedtls/base64.h>
#include <string>

static bool b64url_encode_buf(const uint8_t *data, size_t data_len,
                              char *out_buf, size_t out_max_len)
{
  size_t b64_len = out_max_len;
  ATCA_STATUS status = atcab_base64encode_(data, data_len, out_buf, &b64_len,
                                           atcab_b64rules_urlsafe());

  return (status == ATCA_SUCCESS && b64_len < out_max_len);
}

static bool b64url_decode_buf(const char *in_str, uint8_t *out_buf,
                              size_t expected_len)
{
  if (!in_str || !out_buf)
    return false;

  size_t out_len = expected_len;
  ATCA_STATUS status = atcab_base64decode_(in_str, strlen(in_str), out_buf,
                                           &out_len, atcab_b64rules_urlsafe());

  return (status == ATCA_SUCCESS && out_len == expected_len);
}

#endif // ENCODING_H
