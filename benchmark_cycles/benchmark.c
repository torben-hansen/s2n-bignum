

#include <cpucycles.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <inttypes.h>
#include "s2n-bignum.h"

static void get_random_bytes(size_t num_bytes, uint8_t *out) {
  for (size_t i = 0; i < num_bytes; i++) {
    out[i] = rand();
  }
}

#define OUTER_ITERATIONS 300
#define INNER_ITERATIONS 500
#define WARMUP_ITERATIONS (INNER_ITERATIONS/4)

/*
  Define in scope:
  long long cycles_start;
  long long cycles_end;
  double cycles_temp;
  double cycles_minimal;

  Adopted from https://github.com/Shay-Gueron/AES-GCM-SIV/blob/master/AES_GCM_SIV_128/AES_GCM_SIV_128_C_Intrinsics_Code/measurements.h
*/
#define MEASURE(func) \
  for(size_t warm_up_iterator = 0; warm_up_iterator < WARMUP_ITERATIONS; warm_up_iterator++) \
    { \
      {func}; \
    } \
  cycles_minimal = 1.7976931348623157e+308; \
  for(size_t outer_iterator =0; outer_iterator < OUTER_ITERATIONS; outer_iterator++) { \
    cycles_start = cpucycles(); \
    for (size_t inner_iterator = 0; inner_iterator < INNER_ITERATIONS; inner_iterator++) { \
       {func}; \
    } \
    cycles_end = cpucycles(); \
    cycles_temp = (double) (cycles_end - cycles_start) / INNER_ITERATIONS; \
    if( cycles_minimal > cycles_temp) cycles_minimal = cycles_temp; \
  }

static void print_result(double result, char *func_name) {
  printf("%s: %.0lf\n", func_name, result);
}

static int benchmark_x25519_scalarmulbase() {

  long long cycles_start = 0;
  long long cycles_end = 0;
  double cycles_temp = 0;
  double cycles_minimal = 0;

  uint8_t res[32];
  uint8_t scalar[32];
  get_random_bytes(32, scalar);

#if !defined(ONLY_LEGACY)
  MEASURE(curve25519_x25519base_byte(res, scalar);)
  print_result(cycles_minimal, "curve25519_x25519base_byte()");
#endif

  MEASURE(curve25519_x25519base_byte_alt(res, scalar);)
  print_result(cycles_minimal, "curve25519_x25519base_byte_alt()");
}

static int benchmark_x25519_scalarmulvariable() {

  long long cycles_start = 0;
  long long cycles_end = 0;
  double cycles_temp = 0;
  double cycles_minimal = 0;

  uint8_t res[32];
  uint8_t scalar[32];
  uint8_t scalar_base[32];
  uint8_t point[32];
  get_random_bytes(32, scalar_base);
  get_random_bytes(32, scalar);
  curve25519_x25519base_byte_alt(point, scalar_base);

#if !defined(ONLY_LEGACY)
  MEASURE(curve25519_x25519_byte(res, scalar, point);)
  print_result(cycles_minimal, "curve25519_x25519_byte()");
#endif

  MEASURE(curve25519_x25519_byte_alt(res, scalar, point);)
  print_result(cycles_minimal, "curve25519_x25519_byte_alt()");
}

extern void edwards25519_scalarmulbase(uint64_t res[S2N_BIGNUM_STATIC 8],
  uint64_t scalar[S2N_BIGNUM_STATIC 4]);

static int benchmark_ed25519_scalarmulbase() {

  long long cycles_start = 0;
  long long cycles_end = 0;
  double cycles_temp = 0;
  double cycles_minimal = 0;

  uint64_t res[8];
  uint64_t scalar[4];
  get_random_bytes(sizeof(uint64_t) * 4, (uint8_t *) &scalar[0]);

#if !defined(ONLY_LEGACY)
  MEASURE(edwards25519_scalarmulbase(res, scalar);)
  print_result(cycles_minimal, "edwards25519_scalarmulbase()");
#endif

  MEASURE(edwards25519_scalarmulbase_alt(res, scalar);)
  print_result(cycles_minimal, "edwards25519_scalarmulbase_alt()");
}

static int benchmark_ed25519_scalarmuldouble() {

  long long cycles_start = 0;
  long long cycles_end = 0;
  double cycles_temp = 0;
  double cycles_minimal = 0;

  uint64_t res[8];
  uint64_t scalar[4];
  uint64_t scalar_n[4];
  uint64_t scalar_m[4];
  uint64_t point[8];
  get_random_bytes(sizeof(uint64_t) * 4, (uint8_t *) &scalar[0]);
  get_random_bytes(sizeof(uint64_t) * 4, (uint8_t *) &scalar_n[0]);
  get_random_bytes(sizeof(uint64_t) * 4, (uint8_t *) &scalar_m[0]);
  edwards25519_scalarmulbase_alt(point, scalar);

#if !defined(ONLY_LEGACY)
  MEASURE(edwards25519_scalarmuldouble(res, scalar_n, point, scalar_m);)
  print_result(cycles_minimal, "edwards25519_scalarmuldouble()");
#endif

  MEASURE(edwards25519_scalarmuldouble_alt(res, scalar_n, point, scalar_m);)
  print_result(cycles_minimal, "edwards25519_scalarmuldouble_alt()");
}

static int benchmark_ed25519_decode() {

  long long cycles_start = 0;
  long long cycles_end = 0;
  double cycles_temp = 0;
  double cycles_minimal = 0;

  uint8_t encoded[32];
  uint64_t scalar[4];
  uint64_t point[8];
  uint64_t decoded[8];
  get_random_bytes(sizeof(uint64_t) * 4, (uint8_t *) &scalar[0]);
  edwards25519_scalarmulbase_alt(point, scalar);
  edwards25519_encode(encoded, point);

#if !defined(ONLY_LEGACY)
  MEASURE(edwards25519_decode(decoded, encoded);)
  print_result(cycles_minimal, "edwards25519_decode()");
#endif

  MEASURE(edwards25519_decode_alt(decoded, encoded);)
  print_result(cycles_minimal, "edwards25519_decode_alt()");
}

int main() {
  srand((unsigned int) time(NULL));
  benchmark_x25519_scalarmulbase();
  benchmark_x25519_scalarmulvariable();
  benchmark_ed25519_scalarmulbase();
  benchmark_ed25519_scalarmuldouble();
  benchmark_ed25519_decode();
  return 0;
}
