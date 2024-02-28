#!/bin/bash

# configure
# 1: graviton 2
# 2: graviton 3
# 3: legacy intel
# 4: modern intel
CPU_ARCH=4

# install dependencies
sudo yum groupinstall -y "Development Tools"

# fetch s2-bignum source
git clone https://github.com/torben-hansen/s2n-bignum.git ; \
cd s2n-bignum ; git checkout rwc2024_benchmark

# build s2n-bignum
if [ ${CPU_ARCH} -le 2 ]; then
  # Graviton, arm64
  cd arm; make
else
  cd ./x86; make
fi

# run tests, it's fairly quick
cd ../tests; make go
cd ..

# build libcpucycles
cd libcpucycles-20240114
./configure && sudo make -j8 install
cd ../benchmark_cycles

BUILD_OPTIONS=""
LINK_OPTIONS="-lcpucycles"
INCLUDE_OPTIONS="-I../include/"
if [ ${CPU_ARCH} -ge 3 ]; then
  # build x86
  OBJECT_FILES="../x86/curve25519/curve25519_x25519base.o \
  ../x86/curve25519/curve25519_x25519.o \
  ../x86/curve25519/curve25519_x25519base_alt.o \
  ../x86/curve25519/curve25519_x25519_alt.o \
  ../x86/curve25519/edwards25519_scalarmulbase.o \
  ../x86/curve25519/edwards25519_scalarmulbase_alt.o \
  ../x86/curve25519/edwards25519_scalarmuldouble.o \
  ../x86/curve25519/edwards25519_scalarmuldouble_alt.o \
  ../x86/curve25519/edwards25519_encode.o \
  ../x86/curve25519/edwards25519_decode.o \
  ../x86/curve25519/edwards25519_decode_alt.o"
  if [ ${CPU_ARCH} -eq 3 ]; then
    BUILD_OPTIONS="${BUILD_OPTIONS} -DONLY_LEGACY"
  fi
else
  # Assume arm
  OBJECT_FILES="../arm/curve25519/curve25519_x25519base_byte.o \
  ../arm/curve25519/curve25519_x25519_byte.o \
  ../arm/curve25519/curve25519_x25519base_byte_alt.o \
  ../arm/curve25519/curve25519_x25519_byte_alt.o \
  ../arm/curve25519/edwards25519_scalarmulbase.o \
  ../arm/curve25519/edwards25519_scalarmulbase_alt.o \
  ../arm/curve25519/edwards25519_scalarmuldouble.o \
  ../arm/curve25519/edwards25519_scalarmuldouble_alt.o \
  ../arm/curve25519/edwards25519_encode.o \
  ../arm/curve25519/edwards25519_decode.o \
  ../arm/curve25519/edwards25519_decode_alt.o"
fi

gcc -O0 ${INCLUDE_OPTIONS} ${OBJECT_FILES} ${BUILD_OPTIONS} benchmark.c -o benchmark ${LINK_OPTIONS}

LD_LIBRARY_PATH=/usr/local/lib ./benchmark
