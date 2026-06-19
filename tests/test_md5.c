// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

// ***************************************************************************
// Differential known-answer-test (KAT) gate for the scalar x86-64 MD5
// block-compression routine
//
//   void md5_block_asm_data_order(uint32_t state[4], const uint8_t *data,
//                                 size_t num_blocks);   // SysV: RDI,RSI,RDX
//
// frozen at x86_att/md5/md5_block_asm_data_order.S (emitted by the Ragamuffin
// transpiler). This mirrors the pattern of test_sha3_keccak_f1600 in test.c
// (reference function + random differential loop + known-answer vectors +
// "All OK"), but is kept STANDALONE: it links only the single MD5 object, not
// the whole libs2nbignum.a, and does not touch the public include/s2n-bignum.h.
// Registration of the object into the library / proofs build is deferred to the
// proof's Phase 9 (object/source path canonicalisation), so this gate must not
// front-run that. Build & run from this directory on an x86-64 host:
//
//   make test_md5 && ./test_md5
//
// The gate gives three independent layers of assurance:
//   (1) reference_md5_block on the RFC 1321 vectors reproduces the published
//       digests        -> the C reference itself is genuine MD5;
//   (2) md5_block_asm_data_order on the same vectors reproduces the published
//       digests (incl. the 2-block 62/80-byte vectors, exercising num>1)
//                       -> the assembly is genuine MD5 on those inputs;
//   (3) md5_block_asm_data_order matches reference_md5_block on many random
//       (state, num blocks of data) pairs, plus the num==0 no-op edge case
//                       -> the assembly matches the reference everywhere.
//
// This mechanically catches ABI/clobber/off-by-one/byteswap bugs before any
// HOL Light proof work begins. It is a GATE: it must print "All OK".
// ***************************************************************************

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

// The assembler implementation under test.
// SysV calling convention: RDI = state, RSI = data, RDX = num_blocks.
extern void md5_block_asm_data_order(uint32_t *state, const uint8_t *data,
                                     size_t num);

// ***************************************************************************
// Portable, host-endianness-independent little-endian 32-bit primitives.
// These match the assembly's `movl N(%rsi),%rNd` (a little-endian 32-bit load)
// and the standard MD5 left-rotate by an immediate.
// ***************************************************************************

static uint32_t ref_load_u32_le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void ref_store_u32_le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xff);
  p[1] = (uint8_t)((v >> 8) & 0xff);
  p[2] = (uint8_t)((v >> 16) & 0xff);
  p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t ref_rotl_u32(uint32_t value, int shift) {
  return (value << shift) | (value >> ((-shift) & 31));
}

// ***************************************************************************
// Reference MD5 block compression, ported verbatim (round constants, message
// schedule, rotates, F/G/H/I forms, add-back) from the generic C in aws-lc:
// crypto/fipsmodule/md5/md5.c. The aws-lc original interleaves the message
// loads with round 0 purely for scheduling; here all 16 little-endian words
// are loaded up front, which is functionally identical.
// ***************************************************************************

#define F(b, c, d) ((((c) ^ (d)) & (b)) ^ (d))
#define G(b, c, d) ((((b) ^ (c)) & (d)) ^ (c))
#define H(b, c, d) ((b) ^ (c) ^ (d))
#define I(b, c, d) (((~(d)) | (b)) ^ (c))

#define R0(a, b, c, d, k, s, t)                  \
  do {                                           \
    (a) += ((k) + (t) + F((b), (c), (d)));       \
    (a) = ref_rotl_u32(a, s);                    \
    (a) += (b);                                  \
  } while (0)
#define R1(a, b, c, d, k, s, t)                  \
  do {                                           \
    (a) += ((k) + (t) + G((b), (c), (d)));       \
    (a) = ref_rotl_u32(a, s);                    \
    (a) += (b);                                  \
  } while (0)
#define R2(a, b, c, d, k, s, t)                  \
  do {                                           \
    (a) += ((k) + (t) + H((b), (c), (d)));       \
    (a) = ref_rotl_u32(a, s);                    \
    (a) += (b);                                  \
  } while (0)
#define R3(a, b, c, d, k, s, t)                  \
  do {                                           \
    (a) += ((k) + (t) + I((b), (c), (d)));       \
    (a) = ref_rotl_u32(a, s);                    \
    (a) += (b);                                  \
  } while (0)

static void reference_md5_block(uint32_t *state, const uint8_t *data,
                                size_t num) {
  uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
  uint32_t X[16];

  for (; num--;) {
    for (int i = 0; i < 16; i++) {
      X[i] = ref_load_u32_le(data);
      data += 4;
    }

    // Round 0 (F)
    R0(A, B, C, D, X[0], 7, 0xd76aa478L);
    R0(D, A, B, C, X[1], 12, 0xe8c7b756L);
    R0(C, D, A, B, X[2], 17, 0x242070dbL);
    R0(B, C, D, A, X[3], 22, 0xc1bdceeeL);
    R0(A, B, C, D, X[4], 7, 0xf57c0fafL);
    R0(D, A, B, C, X[5], 12, 0x4787c62aL);
    R0(C, D, A, B, X[6], 17, 0xa8304613L);
    R0(B, C, D, A, X[7], 22, 0xfd469501L);
    R0(A, B, C, D, X[8], 7, 0x698098d8L);
    R0(D, A, B, C, X[9], 12, 0x8b44f7afL);
    R0(C, D, A, B, X[10], 17, 0xffff5bb1L);
    R0(B, C, D, A, X[11], 22, 0x895cd7beL);
    R0(A, B, C, D, X[12], 7, 0x6b901122L);
    R0(D, A, B, C, X[13], 12, 0xfd987193L);
    R0(C, D, A, B, X[14], 17, 0xa679438eL);
    R0(B, C, D, A, X[15], 22, 0x49b40821L);

    // Round 1 (G)
    R1(A, B, C, D, X[1], 5, 0xf61e2562L);
    R1(D, A, B, C, X[6], 9, 0xc040b340L);
    R1(C, D, A, B, X[11], 14, 0x265e5a51L);
    R1(B, C, D, A, X[0], 20, 0xe9b6c7aaL);
    R1(A, B, C, D, X[5], 5, 0xd62f105dL);
    R1(D, A, B, C, X[10], 9, 0x02441453L);
    R1(C, D, A, B, X[15], 14, 0xd8a1e681L);
    R1(B, C, D, A, X[4], 20, 0xe7d3fbc8L);
    R1(A, B, C, D, X[9], 5, 0x21e1cde6L);
    R1(D, A, B, C, X[14], 9, 0xc33707d6L);
    R1(C, D, A, B, X[3], 14, 0xf4d50d87L);
    R1(B, C, D, A, X[8], 20, 0x455a14edL);
    R1(A, B, C, D, X[13], 5, 0xa9e3e905L);
    R1(D, A, B, C, X[2], 9, 0xfcefa3f8L);
    R1(C, D, A, B, X[7], 14, 0x676f02d9L);
    R1(B, C, D, A, X[12], 20, 0x8d2a4c8aL);

    // Round 2 (H)
    R2(A, B, C, D, X[5], 4, 0xfffa3942L);
    R2(D, A, B, C, X[8], 11, 0x8771f681L);
    R2(C, D, A, B, X[11], 16, 0x6d9d6122L);
    R2(B, C, D, A, X[14], 23, 0xfde5380cL);
    R2(A, B, C, D, X[1], 4, 0xa4beea44L);
    R2(D, A, B, C, X[4], 11, 0x4bdecfa9L);
    R2(C, D, A, B, X[7], 16, 0xf6bb4b60L);
    R2(B, C, D, A, X[10], 23, 0xbebfbc70L);
    R2(A, B, C, D, X[13], 4, 0x289b7ec6L);
    R2(D, A, B, C, X[0], 11, 0xeaa127faL);
    R2(C, D, A, B, X[3], 16, 0xd4ef3085L);
    R2(B, C, D, A, X[6], 23, 0x04881d05L);
    R2(A, B, C, D, X[9], 4, 0xd9d4d039L);
    R2(D, A, B, C, X[12], 11, 0xe6db99e5L);
    R2(C, D, A, B, X[15], 16, 0x1fa27cf8L);
    R2(B, C, D, A, X[2], 23, 0xc4ac5665L);

    // Round 3 (I)
    R3(A, B, C, D, X[0], 6, 0xf4292244L);
    R3(D, A, B, C, X[7], 10, 0x432aff97L);
    R3(C, D, A, B, X[14], 15, 0xab9423a7L);
    R3(B, C, D, A, X[5], 21, 0xfc93a039L);
    R3(A, B, C, D, X[12], 6, 0x655b59c3L);
    R3(D, A, B, C, X[3], 10, 0x8f0ccc92L);
    R3(C, D, A, B, X[10], 15, 0xffeff47dL);
    R3(B, C, D, A, X[1], 21, 0x85845dd1L);
    R3(A, B, C, D, X[8], 6, 0x6fa87e4fL);
    R3(D, A, B, C, X[15], 10, 0xfe2ce6e0L);
    R3(C, D, A, B, X[6], 15, 0xa3014314L);
    R3(B, C, D, A, X[13], 21, 0x4e0811a1L);
    R3(A, B, C, D, X[4], 6, 0xf7537e82L);
    R3(D, A, B, C, X[11], 10, 0xbd3af235L);
    R3(C, D, A, B, X[2], 15, 0x2ad7d2bbL);
    R3(B, C, D, A, X[9], 21, 0xeb86d391L);

    A = state[0] += A;
    B = state[1] += B;
    C = state[2] += C;
    D = state[3] += D;
  }
}

#undef F
#undef G
#undef H
#undef I
#undef R0
#undef R1
#undef R2
#undef R3

// ***************************************************************************
// Full-message MD5 wrapper around a block function, so the published RFC 1321
// digest vectors (which include multi-block messages) can be checked directly.
// ***************************************************************************

typedef void (*md5_block_fn)(uint32_t *state, const uint8_t *data, size_t num);

// MD5 of msg[0..len-1] using block_fn, writing 16 digest bytes into out.
// Pads per RFC 1321: append 0x80, zero-fill, then the 64-bit little-endian bit
// length. len is bounded well within a static buffer here.
static void md5_full(md5_block_fn block_fn, const uint8_t *msg, size_t len,
                     uint8_t out[16]) {
  uint8_t buf[256];
  uint32_t h[4] = {0x67452301UL, 0xefcdab89UL, 0x98badcfeUL, 0x10325476UL};

  // Number of 64-byte blocks after padding: room for msg + 0x80 + 8-byte length.
  size_t nblocks = (len + 8) / 64 + 1;
  size_t total = nblocks * 64;
  if (total > sizeof(buf)) {
    fprintf(stderr, "md5_full: message too long for static buffer\n");
    exit(2);
  }

  memset(buf, 0, total);
  memcpy(buf, msg, len);
  buf[len] = 0x80;

  uint64_t bitlen = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) {
    buf[total - 8 + i] = (uint8_t)((bitlen >> (8 * i)) & 0xff);
  }

  block_fn(h, buf, nblocks);

  for (int i = 0; i < 4; i++) {
    ref_store_u32_le(out + 4 * i, h[i]);
  }
}

// ***************************************************************************
// Known-answer vectors: the full RFC 1321 "Test suite", plus the empty string.
// Messages up to 80 bytes; the 62- and 80-byte vectors pad to two blocks and
// thus exercise num_blocks == 2.
// ***************************************************************************

typedef struct {
  const char *msg;
  uint8_t digest[16];
} md5_kat;

static const md5_kat kats[] = {
    {"", {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09,
          0x98, 0xec, 0xf8, 0x42, 0x7e}},
    {"a", {0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99,
           0xe2, 0x69, 0x77, 0x26, 0x61}},
    {"abc", {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f,
             0x7d, 0x28, 0xe1, 0x7f, 0x72}},
    {"message digest", {0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52,
                        0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0}},
    {"abcdefghijklmnopqrstuvwxyz", {0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4,
                                    0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67,
                                    0xe1, 0x3b}},
    {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     {0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c,
      0x9f, 0x41, 0x9d, 0x9f}},
    {"1234567890123456789012345678901234567890123456789012345678901234567890"
     "1234567890",
     {0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e,
      0x21, 0x07, 0xb6, 0x7a}},
};

static int hexcmp_fail(const char *who, const char *msg, const uint8_t *got,
                       const uint8_t *want) {
  printf("Error in md5 KAT (%s) for message \"%s\":\n  got  ", who, msg);
  for (int i = 0; i < 16; i++) printf("%02x", got[i]);
  printf("\n  want ");
  for (int i = 0; i < 16; i++) printf("%02x", want[i]);
  printf("\n");
  return 1;
}

static int test_md5_kat(void) {
  size_t n = sizeof(kats) / sizeof(kats[0]);
  printf("Testing md5_block_asm_data_order against %zu RFC 1321 vectors\n", n);

  for (size_t i = 0; i < n; i++) {
    const uint8_t *m = (const uint8_t *)kats[i].msg;
    size_t len = strlen(kats[i].msg);
    uint8_t dref[16], dasm[16];

    // (1) the C reference must reproduce the published digest.
    md5_full(reference_md5_block, m, len, dref);
    if (memcmp(dref, kats[i].digest, 16) != 0)
      return hexcmp_fail("reference", kats[i].msg, dref, kats[i].digest);

    // (2) the assembly must reproduce the published digest (multi-block too).
    md5_full(md5_block_asm_data_order, m, len, dasm);
    if (memcmp(dasm, kats[i].digest, 16) != 0)
      return hexcmp_fail("asm", kats[i].msg, dasm, kats[i].digest);
  }
  printf("All OK\n");
  return 0;
}

// ***************************************************************************
// Random differential test: asm block fn must match the C reference on random
// (initial state, num blocks of random data) for num in {0,1,2,3,4}.
// ***************************************************************************

static uint8_t rnd_buf[4 * 64];

static int test_md5_random(int reps) {
  printf("Testing md5_block_asm_data_order against C reference, %d cases\n",
         reps);

  for (int t = 0; t < reps; t++) {
    size_t num = (size_t)(rand() % 5);  // 0..4 blocks (0 exercises the guard)

    uint32_t s_ref[4], s_asm[4];
    for (int i = 0; i < 4; i++) {
      uint32_t w = ((uint32_t)(rand() & 0xffff) << 16) |
                   (uint32_t)(rand() & 0xffff);
      s_ref[i] = w;
      s_asm[i] = w;
    }
    for (size_t i = 0; i < num * 64; i++) rnd_buf[i] = (uint8_t)(rand() & 0xff);

    reference_md5_block(s_ref, rnd_buf, num);
    md5_block_asm_data_order(s_asm, rnd_buf, num);

    for (int i = 0; i < 4; i++) {
      if (s_ref[i] != s_asm[i]) {
        printf("Error in md5 differential test (case %d, num=%zu) word %d: "
               "asm = 0x%08" PRIx32 " while reference = 0x%08" PRIx32 "\n",
               t, num, i, s_asm[i], s_ref[i]);
        return 1;
      }
    }
  }
  printf("All OK\n");
  return 0;
}

// ./test_md5 [reps]   (default 100000 random cases)
int main(int argc, char *argv[]) {
  int reps = 100000;
  if (argc >= 2) {
    long r = strtol(argv[1], NULL, 10);
    if (r > 0) reps = (int)r;
  }

  // Deterministic seed so the gate is reproducible.
  srand(0xC0FFEEu);

  int rc = 0;
  rc |= test_md5_kat();
  rc |= test_md5_random(reps);

  if (rc == 0)
    printf("All tests passed\n");
  else
    printf("FAILURE\n");
  return rc;
}
