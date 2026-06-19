(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

(* ========================================================================= *)
(* FIPS-180-4 known-answer validation of the SHA-256 algorithmic spec        *)
(* (x86/proofs/sha256_spec.ml).                                              *)
(*                                                                           *)
(* This file is NOT part of the correctness proof and is not `needs`'d by    *)
(* any proof file.  It is a standalone, reproducible check that the pure     *)
(* HOL-Light spec computes the published FIPS-180-4 digests on the two       *)
(* canonical test vectors ("abc" and the empty string).  Loading this file   *)
(* in a fresh s2n-x86 checkpoint either succeeds silently (both KATs pass)   *)
(* or raises Failure with a mismatching digest.                              *)
(*                                                                           *)
(* The evaluator proves, for a concrete 16-word message m, the theorem       *)
(*   |- sha256_block m sha256_H0 = [word d0; ...; word d7]                    *)
(* by:                                                                       *)
(*   - memoised forward computation of the 64-entry schedule sha256_W,       *)
(*   - one-round-at-a-time unfolding of sha256_compress (avoiding the        *)
(*     infinite loop that REWRITE_CONV[sha256_W] / [sha256_compress] would   *)
(*     trigger on their recursive RHS), and                                  *)
(*   - WORD_REDUCE_CONV to collapse each round's word arithmetic.            *)
(*                                                                           *)
(* It is also a convenience tool for later phases (5-9): given a concrete    *)
(* message and round count it yields the spec's intermediate working state   *)
(* as a theorem, against which a symbolic-execution state can be checked.    *)
(* ========================================================================= *)

needs "x86/proofs/sha256_spec.ml";;

let W32 = WORD_REDUCE_CONV;;

(* Explicit literal for the initial hash, for use as the compression seed. *)
let sha256_h0_lit = rand(concl(REWRITE_CONV[sha256_H0] `sha256_H0`));;

(* Build a (num->int32) message term from 16 integer literals: \t. EL t [..]. *)
let mk_sha256_msg (ws:int list) : term =
  let words = mk_flist
    (map (fun w -> mk_comb(`word:num->int32`, mk_small_numeral w)) ws) in
  mk_abs(`t:num`, mk_comb(mk_comb(`EL:num->(int32)list->int32`,`t:num`), words));;

(* Memoised schedule: returns |- sha256_W m t = word <v>, fully reduced. *)
let sha256_w_cache : (int, thm) Hashtbl.t = Hashtbl.create 80;;

let rec sha256_compute_W (m:term) (t:int) : thm =
  try Hashtbl.find sha256_w_cache t with Not_found ->
  let tm = list_mk_comb(`sha256_W`, [m; mk_small_numeral t]) in
  let th =
    if t < 16 then
      (ONCE_REWRITE_CONV[sha256_W] THENC
       RATOR_CONV(LAND_CONV NUM_REDUCE_CONV) THENC
       REWRITE_CONV[] THENC
       TOP_DEPTH_CONV BETA_CONV THENC EL_CONV THENC W32) tm
    else begin
      let _ = sha256_compute_W m (t-16) and _ = sha256_compute_W m (t-15)
      and _ = sha256_compute_W m (t-7)  and _ = sha256_compute_W m (t-2) in
      let sub = [Hashtbl.find sha256_w_cache (t-16);
                 Hashtbl.find sha256_w_cache (t-15);
                 Hashtbl.find sha256_w_cache (t-7);
                 Hashtbl.find sha256_w_cache (t-2)] in
      (ONCE_REWRITE_CONV[sha256_W] THENC
       RATOR_CONV(LAND_CONV NUM_REDUCE_CONV) THENC
       REWRITE_CONV[] THENC
       ONCE_DEPTH_CONV NUM_REDUCE_CONV THENC
       REWRITE_CONV(sha256_sigma0::sha256_sigma1::sub) THENC
       W32) tm
    end in
  Hashtbl.add sha256_w_cache t th; th;;

let sha256_el_K k =
  (ONCE_REWRITE_CONV[sha256_K] THENC EL_CONV)
    (list_mk_comb(`EL:num->(int32)list->int32`,[mk_small_numeral k; `sha256_K`]));;

let sha256_c2 = CONJUNCT2 sha256_compress;;

(* |- sha256_compress m n h0 = [word a; ...; word h], for concrete n. *)
let sha256_compute_compress (m:term) (n:int) (h0:term) : thm =
  let base0 = list_mk_comb(`sha256_compress`,[m; mk_small_numeral 0; h0]) in
  let st = ref (ONCE_REWRITE_CONV[CONJUNCT1 sha256_compress] base0) in
  for k = 0 to n-1 do
    let step = INST [m,`m:num->int32`; mk_small_numeral k,`n:num`;
                     h0,`s:int32 list`] sha256_c2 in
    let step2 = CONV_RULE (RAND_CONV (RAND_CONV (K !st))) step in
    let kth = sha256_el_K k and wth = Hashtbl.find sha256_w_cache k in
    let red =
      CONV_RULE (RAND_CONV
        (ONCE_REWRITE_CONV[sha256_compress_round] THENC
         REPEATC (CHANGED_CONV let_CONV) THENC
         DEPTH_CONV EL_CONV THENC
         ONCE_DEPTH_CONV NUM_REDUCE_CONV THENC
         REWRITE_CONV[sha256_Ch; sha256_Maj; sha256_Sigma0; sha256_Sigma1] THENC
         REWRITE_CONV[kth; wth] THENC W32)) step2 in
    st := CONV_RULE (LAND_CONV (RATOR_CONV(RAND_CONV NUM_SUC_CONV))) red
  done;
  !st;;

(* Hex digest string of sha256_block m sha256_H0 for a concrete message m. *)
let sha256_block_digest (m:term) : string =
  Hashtbl.clear sha256_w_cache;
  for t = 0 to 63 do ignore(sha256_compute_W m t) done;
  let c64 = sha256_compute_compress m 64 sha256_h0_lit in
  let blk = list_mk_comb(`sha256_block`,[m; sha256_h0_lit]) in
  let bth = (REWRITE_CONV[sha256_block; sha256_addback] THENC
             RAND_CONV(K c64) THENC REWRITE_CONV[MAP2] THENC W32) blk in
  String.concat " "
    (map (fun w -> Printf.sprintf "%08x"
            (Num.int_of_num(dest_numeral(rand w))))
         (dest_list(rand(concl bth))));;

(* ---- The actual known-answer checks (raise Failure on mismatch) ---------- *)

let check_kat name msg_ints expected =
  let got = sha256_block_digest (mk_sha256_msg msg_ints) in
  if got = expected
  then Printf.printf "SHA256 KAT %s: PASS (%s)\n%!" name got
  else failwith (Printf.sprintf "SHA256 KAT %s FAILED: got %s, expected %s"
                   name got expected);;

(* FIPS-180-4 single-block padded messages. *)
(* "abc": 0x61626380 then zeros then bit-length 24 (0x18). *)
check_kat "abc"
  [0x61626380;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0x18]
  "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad";;

(* empty string: 0x80000000 then zeros then bit-length 0. *)
check_kat "empty"
  [0x80000000;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0]
  "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855";;
