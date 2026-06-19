(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

(* ========================================================================= *)
(* Equivalence between the x86 SHA-256 spec round functions                  *)
(* (x86/proofs/sha256_spec.ml) and the architecture-neutral SHA-256 round    *)
(* functions already defined in arm/proofs/sha256.ml (Carl Kwan's ARM        *)
(* intrinsics development).                                                   *)
(*                                                                           *)
(* These bridges let proofs/reductions phrased against the ARM definitions    *)
(* (sha_choose / sha_maj / sha_hash_sigma_0 / sha_hash_sigma_1) compose with  *)
(* the x86 scalar correctness proof, and vice versa.  They are isolated in    *)
(* this separate file so that x86/proofs/sha256_spec.ml stays free of any     *)
(* ARM dependency (no x86 proof file otherwise `needs` an arm/proofs file).   *)
(*                                                                           *)
(* The two Sigma functions are SYNTACTICALLY identical to their ARM           *)
(* counterparts (same word_ror amounts, same xor structure), so they close    *)
(* by REWRITE_TAC.  Ch and Maj are written in a different but logically        *)
(* equivalent bitwise form (FIPS shape vs ARM's optimised shape), so they      *)
(* close by WORD_BITWISE_RULE.                                                 *)
(*                                                                           *)
(* Note: the lowercase message-schedule functions sha256_sigma0/sigma1 have   *)
(* NO counterpart in arm/proofs/sha256.ml (the ARM SHA-256 hardware does the   *)
(* schedule via sha256su0/su1 on packed 128-bit registers, not the scalar     *)
(* sigma recurrence), so there is no equivalence to state for them here.       *)
(* ========================================================================= *)

needs "arm/proofs/sha256.ml";;
needs "x86/proofs/sha256_spec.ml";;

(* Ch: FIPS form (x AND y) XOR (NOT x AND z) = ARM form (x AND (y XOR z)) XOR z *)
let SHA256_CH_EQ_SHA_CHOOSE = prove
 (`!x y z. sha256_Ch x y z = sha_choose x y z`,
  REWRITE_TAC[sha256_Ch; sha_choose] THEN CONV_TAC WORD_BITWISE_RULE);;

(* Maj: FIPS xor form = ARM or form. *)
let SHA256_MAJ_EQ_SHA_MAJ = prove
 (`!x y z. sha256_Maj x y z = sha_maj x y z`,
  REWRITE_TAC[sha256_Maj; sha_maj] THEN CONV_TAC WORD_BITWISE_RULE);;

(* Sigma0 / Sigma1: syntactically identical to the ARM definitions. *)
let SHA256_SIGMA0_EQ_SHA_HASH_SIGMA_0 = prove
 (`!x. sha256_Sigma0 x = sha_hash_sigma_0 x`,
  REWRITE_TAC[sha256_Sigma0; sha_hash_sigma_0]);;

let SHA256_SIGMA1_EQ_SHA_HASH_SIGMA_1 = prove
 (`!x. sha256_Sigma1 x = sha_hash_sigma_1 x`,
  REWRITE_TAC[sha256_Sigma1; sha_hash_sigma_1]);;
