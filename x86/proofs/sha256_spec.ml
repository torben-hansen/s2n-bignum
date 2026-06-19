(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

(* ========================================================================= *)
(* SHA-256 algorithmic specification (FIPS-180-4 Section 6.2 block compress). *)
(*                                                                           *)
(* This is the pure HOL Light ground-truth spec used by the x86-64 scalar    *)
(* sha256_block_data_order_nohw correctness proof.  It is a direct mirror of  *)
(* the validated C reference in tests/test.c (reference_sha256_block):        *)
(* no message padding, no length append, no final byte-swap of the state --   *)
(* exactly the multi-block compression of 64-byte big-endian blocks against   *)
(* the standard K256 constants and the FIPS Sigma/sigma round functions.      *)
(*                                                                           *)
(* Representation choices:                                                    *)
(*   - 32-bit words are :int32 (= 32 word).                                   *)
(*   - The working state a..h is an int32 list of length 8 (EL-indexable),    *)
(*     ordered [a; b; c; d; e; f; g; h].                                      *)
(*   - The per-block message is a function (num->int32): word t (big-endian   *)
(*     load of data[4t..4t+3]) for t < 16.                                    *)
(*   - The multi-block input "data" is a function (num->int32) indexing all   *)
(*     32-bit message words; block i consumes data(16*i) .. data(16*i+15).    *)
(* ========================================================================= *)

needs "Library/words.ml";;

(* ------------------------------------------------------------------------- *)
(* Round functions (FIPS-180-4 4.1.2).                                        *)
(*   Ch(x,y,z)  = (x AND y) XOR (NOT x AND z)                                  *)
(*   Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)                        *)
(*   Sigma0(x)  = ROTR2  x XOR ROTR13 x XOR ROTR22 x                           *)
(*   Sigma1(x)  = ROTR6  x XOR ROTR11 x XOR ROTR25 x                           *)
(*   sigma0(x)  = ROTR7  x XOR ROTR18 x XOR SHR3   x                           *)
(*   sigma1(x)  = ROTR17 x XOR ROTR19 x XOR SHR10  x                           *)
(* ------------------------------------------------------------------------- *)

let sha256_Ch = new_definition
  `sha256_Ch (x:int32) (y:int32) (z:int32) : int32 =
        word_xor (word_and x y) (word_and (word_not x) z)`;;

let sha256_Maj = new_definition
  `sha256_Maj (x:int32) (y:int32) (z:int32) : int32 =
        word_xor (word_and x y) (word_xor (word_and x z) (word_and y z))`;;

let sha256_Sigma0 = new_definition
  `sha256_Sigma0 (x:int32) : int32 =
        word_xor (word_ror x 2) (word_xor (word_ror x 13) (word_ror x 22))`;;

let sha256_Sigma1 = new_definition
  `sha256_Sigma1 (x:int32) : int32 =
        word_xor (word_ror x 6) (word_xor (word_ror x 11) (word_ror x 25))`;;

let sha256_sigma0 = new_definition
  `sha256_sigma0 (x:int32) : int32 =
        word_xor (word_ror x 7) (word_xor (word_ror x 18) (word_ushr x 3))`;;

let sha256_sigma1 = new_definition
  `sha256_sigma1 (x:int32) : int32 =
        word_xor (word_ror x 17) (word_xor (word_ror x 19) (word_ushr x 10))`;;

(* ------------------------------------------------------------------------- *)
(* The 64 round constants K256 (FIPS-180-4 4.2.2), as an int32 list.          *)
(* These are the STANDARD 64 constants (NOT the doubled 128-entry asm table). *)
(* ------------------------------------------------------------------------- *)

let sha256_K = new_definition
  `sha256_K : int32 list =
   [word 0x428a2f98; word 0x71374491; word 0xb5c0fbcf; word 0xe9b5dba5;
    word 0x3956c25b; word 0x59f111f1; word 0x923f82a4; word 0xab1c5ed5;
    word 0xd807aa98; word 0x12835b01; word 0x243185be; word 0x550c7dc3;
    word 0x72be5d74; word 0x80deb1fe; word 0x9bdc06a7; word 0xc19bf174;
    word 0xe49b69c1; word 0xefbe4786; word 0x0fc19dc6; word 0x240ca1cc;
    word 0x2de92c6f; word 0x4a7484aa; word 0x5cb0a9dc; word 0x76f988da;
    word 0x983e5152; word 0xa831c66d; word 0xb00327c8; word 0xbf597fc7;
    word 0xc6e00bf3; word 0xd5a79147; word 0x06ca6351; word 0x14292967;
    word 0x27b70a85; word 0x2e1b2138; word 0x4d2c6dfc; word 0x53380d13;
    word 0x650a7354; word 0x766a0abb; word 0x81c2c92e; word 0x92722c85;
    word 0xa2bfe8a1; word 0xa81a664b; word 0xc24b8b70; word 0xc76c51a3;
    word 0xd192e819; word 0xd6990624; word 0xf40e3585; word 0x106aa070;
    word 0x19a4c116; word 0x1e376c08; word 0x2748774c; word 0x34b0bcb5;
    word 0x391c0cb3; word 0x4ed8aa4a; word 0x5b9cca4f; word 0x682e6ff3;
    word 0x748f82ee; word 0x78a5636f; word 0x84c87814; word 0x8cc70208;
    word 0x90befffa; word 0xa4506ceb; word 0xbef9a3f7; word 0xc67178f2]`;;

(* ------------------------------------------------------------------------- *)
(* The initial hash value H0 (FIPS-180-4 5.3.3), as an int32 list of len 8.   *)
(* ------------------------------------------------------------------------- *)

let sha256_H0 = new_definition
  `sha256_H0 : int32 list =
   [word 0x6a09e667; word 0xbb67ae85; word 0x3c6ef372; word 0xa54ff53a;
    word 0x510e527f; word 0x9b05688c; word 0x1f83d9ab; word 0x5be0cd19]`;;

(* ------------------------------------------------------------------------- *)
(* The message schedule W (FIPS-180-4 6.2.2).  Parameterised by the 16 input  *)
(* words m : num->int32.  For t < 16, W t = m t; otherwise the standard        *)
(* recurrence.  Well-founded because t-16, t-15, t-7, t-2 are all < t when     *)
(* t >= 16.                                                                    *)
(* ------------------------------------------------------------------------- *)

let sha256_W = define
  `sha256_W (m:num->int32) (t:num) : int32 =
        if t < 16 then m t
        else word_add
               (word_add (sha256_W m (t - 16)) (sha256_sigma0 (sha256_W m (t - 15))))
               (word_add (sha256_W m (t - 7))  (sha256_sigma1 (sha256_W m (t - 2))))`;;

(* ------------------------------------------------------------------------- *)
(* One compression round (FIPS-180-4 6.2.2 step 3).  Takes the schedule       *)
(* function m, the round index t, and the working state [a;b;c;d;e;f;g;h];     *)
(* returns the updated state.                                                  *)
(*   T1 = h + Sigma1 e + Ch e f g + K t + W m t                                *)
(*   T2 = Sigma0 a + Maj a b c                                                 *)
(*   a' = T1 + T2;  e' = d + T1;  the rest shift down.                          *)
(* ------------------------------------------------------------------------- *)

let sha256_compress_round = new_definition
  `sha256_compress_round (m:num->int32) (t:num) (s:int32 list) : int32 list =
        let a = EL 0 s and b = EL 1 s and c = EL 2 s and d = EL 3 s
        and e = EL 4 s and f = EL 5 s and g = EL 6 s and h = EL 7 s in
        let t1 = word_add (word_add h (sha256_Sigma1 e))
                          (word_add (sha256_Ch e f g)
                                    (word_add (EL t sha256_K) (sha256_W m t))) in
        let t2 = word_add (sha256_Sigma0 a) (sha256_Maj a b c) in
        [word_add t1 t2; a; b; c; word_add d t1; e; f; g]`;;

(* Iterate n compression rounds, starting at round 0. *)
let sha256_compress = define
  `(sha256_compress (m:num->int32) 0 (s:int32 list) = s) /\
   (sha256_compress (m:num->int32) (SUC n) (s:int32 list) =
        sha256_compress_round m n (sha256_compress m n s))`;;

(* ------------------------------------------------------------------------- *)
(* Add the post-compression working state back into the incoming hash         *)
(* (FIPS-180-4 6.2.2 step 4): elementwise word_add of two length-8 lists.     *)
(* ------------------------------------------------------------------------- *)

let sha256_addback = new_definition
  `sha256_addback (h:int32 list) (s:int32 list) : int32 list =
        MAP2 word_add h s`;;

(* ------------------------------------------------------------------------- *)
(* One full 64-round block compression of message m starting from hash h.     *)
(* ------------------------------------------------------------------------- *)

let sha256_block = new_definition
  `sha256_block (m:num->int32) (h:int32 list) : int32 list =
        sha256_addback h (sha256_compress m 64 h)`;;

(* ------------------------------------------------------------------------- *)
(* Multi-block hashing.  data : num->int32 indexes all 32-bit message words;  *)
(* block i consumes data(16*i) .. data(16*i+15).  Returns the hash after the  *)
(* first n blocks, starting from h.                                           *)
(* ------------------------------------------------------------------------- *)

let sha256_hash_blocks = define
  `(sha256_hash_blocks 0 (data:num->int32) (h:int32 list) = h) /\
   (sha256_hash_blocks (SUC i) (data:num->int32) (h:int32 list) =
        sha256_block (\t. data (16 * i + t)) (sha256_hash_blocks i data h))`;;

(* ========================================================================= *)
(* LENGTH preservation lemmas.                                               *)
(*                                                                           *)
(* The working state is always an 8-element int32 list, the round-constant   *)
(* table K256 has length 64, and H0 has length 8.  These let later phases     *)
(* index the state by EL 0..7 and discharge LENGTH side conditions of         *)
(* MAP2/EL lemmas without re-deriving them.                                    *)
(* ========================================================================= *)

let SHA256_K_LENGTH = prove
 (`LENGTH sha256_K = 64`,
  REWRITE_TAC[sha256_K; LENGTH] THEN ARITH_TAC);;

let SHA256_H0_LENGTH = prove
 (`LENGTH sha256_H0 = 8`,
  REWRITE_TAC[sha256_H0; LENGTH] THEN ARITH_TAC);;

(* One compression round always returns an explicit 8-element list, so its    *)
(* length is 8 unconditionally (independent of the input state's length).     *)
let SHA256_COMPRESS_ROUND_LENGTH = prove
 (`!m t s. LENGTH(sha256_compress_round m t s) = 8`,
  REPEAT GEN_TAC THEN REWRITE_TAC[sha256_compress_round] THEN
  CONV_TAC(DEPTH_CONV let_CONV) THEN REWRITE_TAC[LENGTH] THEN ARITH_TAC);;

(* Iterated compression preserves a length-8 state. *)
let SHA256_COMPRESS_LENGTH = prove
 (`!m n s. LENGTH s = 8 ==> LENGTH(sha256_compress m n s) = 8`,
  GEN_TAC THEN INDUCT_TAC THEN
  REWRITE_TAC[sha256_compress; SHA256_COMPRESS_ROUND_LENGTH] THEN
  ASM_SIMP_TAC[]);;

(* The add-back step preserves length when the two arguments agree in length. *)
let SHA256_ADDBACK_LENGTH = prove
 (`!h s. LENGTH h = LENGTH s ==> LENGTH(sha256_addback h s) = LENGTH s`,
  REWRITE_TAC[sha256_addback] THEN MESON_TAC[LENGTH_MAP2]);;

(* A full block compression preserves a length-8 hash state. *)
let SHA256_BLOCK_LENGTH = prove
 (`!m h. LENGTH h = 8 ==> LENGTH(sha256_block m h) = 8`,
  REPEAT STRIP_TAC THEN REWRITE_TAC[sha256_block; sha256_addback] THEN
  ASM_MESON_TAC[LENGTH_MAP2; SHA256_COMPRESS_LENGTH]);;

(* Multi-block hashing preserves a length-8 hash state. *)
let SHA256_HASH_BLOCKS_LENGTH = prove
 (`!n data h. LENGTH h = 8 ==> LENGTH(sha256_hash_blocks n data h) = 8`,
  INDUCT_TAC THEN ASM_SIMP_TAC[sha256_hash_blocks; SHA256_BLOCK_LENGTH]);;
