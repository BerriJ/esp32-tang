#include "mbedtls/bignum.h"
#include <string.h>
#include <stdio.h>

// P-256 Curve Parameters
const char *P256_P = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
const char *P256_B = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";

/**
 * @brief Computes the two possible Y coordinates for a given X on the P-256 curve.
 * * @param x_bytes  Input: 32-byte X coordinate
 * @param y1_bytes Output: 32-byte buffer for the first possible Y
 * @param y2_bytes Output: 32-byte buffer for the second possible Y
 * @return 0 on success, non-zero on error
 */
int compute_p256_y_from_x(const uint8_t x_bytes[32], uint8_t y1_bytes[32], uint8_t y2_bytes[32])
{
  mbedtls_mpi x, p, b, v, y1, y2, three, exp;
  int ret = 0;

  // Initialize all Big Integer variables
  mbedtls_mpi_init(&x);
  mbedtls_mpi_init(&p);
  mbedtls_mpi_init(&b);
  mbedtls_mpi_init(&v);
  mbedtls_mpi_init(&y1);
  mbedtls_mpi_init(&y2);
  mbedtls_mpi_init(&three);
  mbedtls_mpi_init(&exp);

  // Load values
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&x, x_bytes, 32));
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&p, 16, P256_P));
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&b, 16, P256_B));
  MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&three, 3));

  // 1. Calculate v = (x^3 - 3x + b) mod p
  // v = x^2
  MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&v, &x, &x));
  MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&v, &v, &p));
  // v = x^3
  MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&v, &v, &x));
  MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&v, &v, &p));

  // y1 = 3x (temporarily using y1 as a working variable)
  MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&y1, &three, &x));
  MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&y1, &y1, &p));

  // v = x^3 - 3x
  MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&v, &v, &y1));
  if (mbedtls_mpi_cmp_int(&v, 0) < 0)
  {
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&v, &v, &p)); // keep it positive mod p
  }

  // v = x^3 - 3x + b
  MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&v, &v, &b));
  MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&v, &v, &p));

  // 2. Calculate the square root: y1 = v^((p+1)/4) mod p
  // exp = p + 1
  MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&exp, &p, 1));
  // exp = (p + 1) / 4  (right shift by 2 bits)
  MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&exp, 2));

  // y1 = v^exp mod p
  MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&y1, &v, &exp, &p, NULL));

  // 3. Calculate y2 = p - y1
  MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&y2, &p, &y1));

  // 4. Write out the 32-byte results
  MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&y1, y1_bytes, 32));
  MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&y2, y2_bytes, 32));

cleanup:
  // Free memory to prevent leaks
  mbedtls_mpi_free(&x);
  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&b);
  mbedtls_mpi_free(&v);
  mbedtls_mpi_free(&y1);
  mbedtls_mpi_free(&y2);
  mbedtls_mpi_free(&three);
  mbedtls_mpi_free(&exp);

  return ret;
}