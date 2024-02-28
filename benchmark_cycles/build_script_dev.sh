#!/bin/bash

CPU_ARCH=4

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
