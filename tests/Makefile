#############################################################################
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
#############################################################################

.PHONY: clean ctCheck md5kat md5test

# Set ARCH to "x86" or "arm" as appropriate; this is literally the
# directory name in which the libs2nbignum.a file should be found.
# If this block fails to do it automatically, replace with manual
# setting: ARCH=x86 or ARCH=arm as appropriate

ARCH=unknown_architecture
VALGRIND?=

UNAME_RESULT=$(shell uname -m)

ifeq ($(UNAME_RESULT),x86_64)
ARCH=x86
endif

ifeq ($(UNAME_RESULT),aarch64)
ARCH=arm
endif

ifeq ($(UNAME_RESULT),arm64)
ARCH=arm
endif

# Build the test program "test". This can then be invoked, optionally
# with a parameter with the number of tests per function, e.g.
#
#   ./test 10
#
# The "go" target runs it with 100 tests per function and filters
# most of the "good result" output to leave the summary and errors
#
# "complete" runs all tests regardless of architecture including
# the known value tests, doing no filtering of output and giving a
# return code.

default: test ctCheck;

go: test; ./test +100 | grep -v OK

complete: test ctCheck; $(VALGRIND) ./test +500

test: test.c known_value_tests_p384.h tweetnacl_excerpt.c ../include/s2n-bignum.h ../$(ARCH)/libs2nbignum.a; $(CC) -Wall -std=gnu99 -o test test.c -L../$(ARCH) -ls2nbignum -lm

clean: ;
	rm -f test
	rm -f test_md5
	rm -f ctCheck

# The scalar x86-64 MD5 block routine md5_block_asm_data_order is folded into
# the main test harness (test.c: test_md5_block_asm_data_order +
# functionaltest(all,...)), so it runs under `make go`/`make complete`/CI like
# every other routine.  `md5test` runs just that case via the main binary; the
# leading '-' ignores the binary's nonzero exit, which it always returns when a
# name filter selects a subset (it returns 0 only when EVERY test ran).

md5test: test; -./test md5_block_asm_data_order

# Standalone differential KAT gate, retained as an independent reproducible
# check: compiles directly against the frozen .S (so it does not depend on
# libs2nbignum.a or the gitignored .o), and additionally verifies the RFC 1321
# published digest vectors (which the in-harness differential test does not).
# Must print "All OK"/"All tests passed".

MD5_ASM=../x86/md5/md5_block_asm_data_order.S

test_md5: test_md5.c $(MD5_ASM); $(CC) -Wall -std=gnu99 -I../include -DWINDOWS_ABI=0 -o test_md5 test_md5.c $(MD5_ASM)

md5kat: test_md5; ./test_md5

ctCheck:
	rm -f ctCheck
	for f in `find ../$(ARCH)/p* ../$(ARCH)/secp* -name '*.o' | grep -v bignum_inv_p | grep -v bignum_montinv_p | grep -v _scalarmul | grep -v _montjscalarmul | grep -v _jscalarmul`; do trimmed=`echo $$f | tr -d .`; objdump -d --no-show-raw-insn $$f | grep '^[ \t]' | cut -f2 -d: -s | awk "{print \"$$trimmed: \" \$$1}" | grep -v -f ../non_ct_functions.txt |  grep -v -f ../$(ARCH)/allowed_asm >> ctCheck && echo FAIL >> ctCheck; done || true
	! grep FAIL ctCheck
