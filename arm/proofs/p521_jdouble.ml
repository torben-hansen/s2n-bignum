(*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0
 *)

(* ========================================================================= *)
(* Point doubling in Jacobian coordinates for NIST p521 curve.               *)
(* ========================================================================= *)

needs "arm/proofs/base.ml";;
needs "common/ecencoding.ml";;
needs "EC/jacobian.ml";;
needs "EC/nistp521.ml";;

prioritize_int();;
prioritize_real();;
prioritize_num();;

(**** print_literal_from_elf "arm/p521/p521_jdouble.o";;
 ****)

let p521_jdouble_mc = define_assert_from_elf
  "p521_jdouble_mc" "arm/p521/p521_jdouble.o"
[
  0xa9bf53f3;       (* arm_STP X19 X20 SP (Preimmediate_Offset (iword (-- &16))) *)
  0xa9bf5bf5;       (* arm_STP X21 X22 SP (Preimmediate_Offset (iword (-- &16))) *)
  0xa9bf63f7;       (* arm_STP X23 X24 SP (Preimmediate_Offset (iword (-- &16))) *)
  0xa9bf6bf9;       (* arm_STP X25 X26 SP (Preimmediate_Offset (iword (-- &16))) *)
  0xa9bf73fb;       (* arm_STP X27 X28 SP (Preimmediate_Offset (iword (-- &16))) *)
  0xd10803ff;       (* arm_SUB SP SP (rvalue (word 512)) *)
  0xaa0003fa;       (* arm_MOV X26 X0 *)
  0xaa0103fb;       (* arm_MOV X27 X1 *)
  0xa9490f62;       (* arm_LDP X2 X3 X27 (Immediate_Offset (iword (&144))) *)
  0xa94a1764;       (* arm_LDP X4 X5 X27 (Immediate_Offset (iword (&160))) *)
  0xa94b1f66;       (* arm_LDP X6 X7 X27 (Immediate_Offset (iword (&176))) *)
  0xa94c2768;       (* arm_LDP X8 X9 X27 (Immediate_Offset (iword (&192))) *)
  0x9b087ccc;       (* arm_MUL X12 X6 X8 *)
  0x9b097cf1;       (* arm_MUL X17 X7 X9 *)
  0x9bc87cd6;       (* arm_UMULH X22 X6 X8 *)
  0xeb0700d7;       (* arm_SUBS X23 X6 X7 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb08012a;       (* arm_SUBS X10 X9 X8 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc97cf7;       (* arm_UMULH X23 X7 X9 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b067cca;       (* arm_MUL X10 X6 X6 *)
  0x9b077cf0;       (* arm_MUL X16 X7 X7 *)
  0x9b077cd5;       (* arm_MUL X21 X6 X7 *)
  0x9bc67ccb;       (* arm_UMULH X11 X6 X6 *)
  0x9bc77cf1;       (* arm_UMULH X17 X7 X7 *)
  0x9bc77cd4;       (* arm_UMULH X20 X6 X7 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b087d0e;       (* arm_MUL X14 X8 X8 *)
  0x9b097d30;       (* arm_MUL X16 X9 X9 *)
  0x9b097d15;       (* arm_MUL X21 X8 X9 *)
  0x9bc87d0f;       (* arm_UMULH X15 X8 X8 *)
  0x9bc97d31;       (* arm_UMULH X17 X9 X9 *)
  0x9bc97d14;       (* arm_UMULH X20 X8 X9 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xf9406b73;       (* arm_LDR X19 X27 (Immediate_Offset (word 208)) *)
  0x8b130277;       (* arm_ADD X23 X19 X19 *)
  0x9b137e73;       (* arm_MUL X19 X19 X19 *)
  0x9240cc55;       (* arm_AND X21 X2 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0x93c2d074;       (* arm_EXTR X20 X3 X2 52 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d53296;       (* arm_EXTR X22 X20 X21 12 *)
  0xab16014a;       (* arm_ADDS X10 X10 X22 *)
  0x93c3a095;       (* arm_EXTR X21 X4 X3 40 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d462b6;       (* arm_EXTR X22 X21 X20 24 *)
  0xba16016b;       (* arm_ADCS X11 X11 X22 *)
  0x93c470b4;       (* arm_EXTR X20 X5 X4 28 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d59296;       (* arm_EXTR X22 X20 X21 36 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0x93c540d5;       (* arm_EXTR X21 X6 X5 16 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d4c2b6;       (* arm_EXTR X22 X21 X20 48 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xd344fcd4;       (* arm_LSR X20 X6 4 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5f298;       (* arm_EXTR X24 X20 X21 60 *)
  0x93c6e0f5;       (* arm_EXTR X21 X7 X6 56 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd378df18;       (* arm_LSL X24 X24 8 *)
  0x93d822b6;       (* arm_EXTR X22 X21 X24 8 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0x93c7b114;       (* arm_EXTR X20 X8 X7 44 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d55296;       (* arm_EXTR X22 X20 X21 20 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0x93c88135;       (* arm_EXTR X21 X9 X8 32 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d482b6;       (* arm_EXTR X22 X21 X20 32 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xd354fd34;       (* arm_LSR X20 X9 20 *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5b296;       (* arm_EXTR X22 X20 X21 44 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0xd36cfe94;       (* arm_LSR X20 X20 44 *)
  0x9a140273;       (* arm_ADC X19 X19 X20 *)
  0x93ca2575;       (* arm_EXTR X21 X11 X10 9 *)
  0x93cb2594;       (* arm_EXTR X20 X12 X11 9 *)
  0xa90053f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&0))) *)
  0x93cc25b5;       (* arm_EXTR X21 X13 X12 9 *)
  0x93cd25d4;       (* arm_EXTR X20 X14 X13 9 *)
  0xa90153f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&16))) *)
  0x93ce25f5;       (* arm_EXTR X21 X15 X14 9 *)
  0x93cf2614;       (* arm_EXTR X20 X16 X15 9 *)
  0xa90253f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&32))) *)
  0x93d02635;       (* arm_EXTR X21 X17 X16 9 *)
  0x93d12674;       (* arm_EXTR X20 X19 X17 9 *)
  0xa90353f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&48))) *)
  0x92402156;       (* arm_AND X22 X10 (rvalue (word 511)) *)
  0xd349fe73;       (* arm_LSR X19 X19 9 *)
  0x8b1302d6;       (* arm_ADD X22 X22 X19 *)
  0xf90023f6;       (* arm_STR X22 SP (Immediate_Offset (word 64)) *)
  0x9b047c4c;       (* arm_MUL X12 X2 X4 *)
  0x9b057c71;       (* arm_MUL X17 X3 X5 *)
  0x9bc47c56;       (* arm_UMULH X22 X2 X4 *)
  0xeb030057;       (* arm_SUBS X23 X2 X3 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb0400aa;       (* arm_SUBS X10 X5 X4 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc57c77;       (* arm_UMULH X23 X3 X5 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b027c4a;       (* arm_MUL X10 X2 X2 *)
  0x9b037c70;       (* arm_MUL X16 X3 X3 *)
  0x9b037c55;       (* arm_MUL X21 X2 X3 *)
  0x9bc27c4b;       (* arm_UMULH X11 X2 X2 *)
  0x9bc37c71;       (* arm_UMULH X17 X3 X3 *)
  0x9bc37c54;       (* arm_UMULH X20 X2 X3 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b047c8e;       (* arm_MUL X14 X4 X4 *)
  0x9b057cb0;       (* arm_MUL X16 X5 X5 *)
  0x9b057c95;       (* arm_MUL X21 X4 X5 *)
  0x9bc47c8f;       (* arm_UMULH X15 X4 X4 *)
  0x9bc57cb1;       (* arm_UMULH X17 X5 X5 *)
  0x9bc57c94;       (* arm_UMULH X20 X4 X5 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xa94053f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&0))) *)
  0xab0a02b5;       (* arm_ADDS X21 X21 X10 *)
  0xba0b0294;       (* arm_ADCS X20 X20 X11 *)
  0xa90053f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&0))) *)
  0xa94153f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&16))) *)
  0xba0c02b5;       (* arm_ADCS X21 X21 X12 *)
  0xba0d0294;       (* arm_ADCS X20 X20 X13 *)
  0xa90153f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&16))) *)
  0xa94253f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&32))) *)
  0xba0e02b5;       (* arm_ADCS X21 X21 X14 *)
  0xba0f0294;       (* arm_ADCS X20 X20 X15 *)
  0xa90253f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&32))) *)
  0xa94353f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&48))) *)
  0xba1002b5;       (* arm_ADCS X21 X21 X16 *)
  0xba110294;       (* arm_ADCS X20 X20 X17 *)
  0xa90353f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&48))) *)
  0xf94023f6;       (* arm_LDR X22 SP (Immediate_Offset (word 64)) *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0xf90023f6;       (* arm_STR X22 SP (Immediate_Offset (word 64)) *)
  0x9b067c4a;       (* arm_MUL X10 X2 X6 *)
  0x9b077c6e;       (* arm_MUL X14 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9bc67c51;       (* arm_UMULH X17 X2 X6 *)
  0xab1101ce;       (* arm_ADDS X14 X14 X17 *)
  0x9bc77c71;       (* arm_UMULH X17 X3 X7 *)
  0xba1101ef;       (* arm_ADCS X15 X15 X17 *)
  0x9bc87c91;       (* arm_UMULH X17 X4 X8 *)
  0xba110210;       (* arm_ADCS X16 X16 X17 *)
  0x9bc97cb1;       (* arm_UMULH X17 X5 X9 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab0a01cb;       (* arm_ADDS X11 X14 X10 *)
  0xba0e01ee;       (* arm_ADCS X14 X15 X14 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xab0a01cc;       (* arm_ADDS X12 X14 X10 *)
  0xba0b01ed;       (* arm_ADCS X13 X15 X11 *)
  0xba0e020e;       (* arm_ADCS X14 X16 X14 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba1003f0;       (* arm_ADCS X16 XZR X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xeb050096;       (* arm_SUBS X22 X4 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb080134;       (* arm_SUBS X20 X9 X8 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb030056;       (* arm_SUBS X22 X2 X3 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb0600f4;       (* arm_SUBS X20 X7 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15016b;       (* arm_ADCS X11 X11 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba14018c;       (* arm_ADCS X12 X12 X20 *)
  0xba1301ad;       (* arm_ADCS X13 X13 X19 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050076;       (* arm_SUBS X22 X3 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070134;       (* arm_SUBS X20 X9 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ef;       (* arm_ADCS X15 X15 X20 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040056;       (* arm_SUBS X22 X2 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060114;       (* arm_SUBS X20 X8 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15018c;       (* arm_ADCS X12 X12 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ad;       (* arm_ADCS X13 X13 X20 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050056;       (* arm_SUBS X22 X2 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060134;       (* arm_SUBS X20 X9 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040076;       (* arm_SUBS X22 X3 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070114;       (* arm_SUBS X20 X8 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xa94053f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&0))) *)
  0x93ce21e2;       (* arm_EXTR X2 X15 X14 8 *)
  0xab150042;       (* arm_ADDS X2 X2 X21 *)
  0x93cf2203;       (* arm_EXTR X3 X16 X15 8 *)
  0xba140063;       (* arm_ADCS X3 X3 X20 *)
  0xa94153f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&16))) *)
  0x93d02224;       (* arm_EXTR X4 X17 X16 8 *)
  0xba150084;       (* arm_ADCS X4 X4 X21 *)
  0x8a040076;       (* arm_AND X22 X3 X4 *)
  0xd348fe25;       (* arm_LSR X5 X17 8 *)
  0xba1400a5;       (* arm_ADCS X5 X5 X20 *)
  0x8a0502d6;       (* arm_AND X22 X22 X5 *)
  0xa94253f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&32))) *)
  0xd37ff946;       (* arm_LSL X6 X10 1 *)
  0xba1500c6;       (* arm_ADCS X6 X6 X21 *)
  0x8a0602d6;       (* arm_AND X22 X22 X6 *)
  0x93cafd67;       (* arm_EXTR X7 X11 X10 63 *)
  0xba1400e7;       (* arm_ADCS X7 X7 X20 *)
  0x8a0702d6;       (* arm_AND X22 X22 X7 *)
  0xa94353f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&48))) *)
  0x93cbfd88;       (* arm_EXTR X8 X12 X11 63 *)
  0xba150108;       (* arm_ADCS X8 X8 X21 *)
  0x8a0802d6;       (* arm_AND X22 X22 X8 *)
  0x93ccfda9;       (* arm_EXTR X9 X13 X12 63 *)
  0xba140129;       (* arm_ADCS X9 X9 X20 *)
  0x8a0902d6;       (* arm_AND X22 X22 X9 *)
  0xf94023f5;       (* arm_LDR X21 SP (Immediate_Offset (word 64)) *)
  0x93cdfdca;       (* arm_EXTR X10 X14 X13 63 *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0x9a0a02aa;       (* arm_ADC X10 X21 X10 *)
  0xd349fd54;       (* arm_LSR X20 X10 9 *)
  0xb277d94a;       (* arm_ORR X10 X10 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba14005f;       (* arm_ADCS XZR X2 X20 *)
  0xba1f02df;       (* arm_ADCS XZR X22 XZR *)
  0xba1f015f;       (* arm_ADCS XZR X10 XZR *)
  0xba140042;       (* arm_ADCS X2 X2 X20 *)
  0xba1f0063;       (* arm_ADCS X3 X3 XZR *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0x9a1f014a;       (* arm_ADC X10 X10 XZR *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0xa9000fe2;       (* arm_STP X2 X3 SP (Immediate_Offset (iword (&0))) *)
  0xa90117e4;       (* arm_STP X4 X5 SP (Immediate_Offset (iword (&16))) *)
  0xa9021fe6;       (* arm_STP X6 X7 SP (Immediate_Offset (iword (&32))) *)
  0xa90327e8;       (* arm_STP X8 X9 SP (Immediate_Offset (iword (&48))) *)
  0xf90023ea;       (* arm_STR X10 SP (Immediate_Offset (word 64)) *)
  0xa9448f62;       (* arm_LDP X2 X3 X27 (Immediate_Offset (iword (&72))) *)
  0xa9459764;       (* arm_LDP X4 X5 X27 (Immediate_Offset (iword (&88))) *)
  0xa9469f66;       (* arm_LDP X6 X7 X27 (Immediate_Offset (iword (&104))) *)
  0xa947a768;       (* arm_LDP X8 X9 X27 (Immediate_Offset (iword (&120))) *)
  0x9b087ccc;       (* arm_MUL X12 X6 X8 *)
  0x9b097cf1;       (* arm_MUL X17 X7 X9 *)
  0x9bc87cd6;       (* arm_UMULH X22 X6 X8 *)
  0xeb0700d7;       (* arm_SUBS X23 X6 X7 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb08012a;       (* arm_SUBS X10 X9 X8 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc97cf7;       (* arm_UMULH X23 X7 X9 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b067cca;       (* arm_MUL X10 X6 X6 *)
  0x9b077cf0;       (* arm_MUL X16 X7 X7 *)
  0x9b077cd5;       (* arm_MUL X21 X6 X7 *)
  0x9bc67ccb;       (* arm_UMULH X11 X6 X6 *)
  0x9bc77cf1;       (* arm_UMULH X17 X7 X7 *)
  0x9bc77cd4;       (* arm_UMULH X20 X6 X7 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b087d0e;       (* arm_MUL X14 X8 X8 *)
  0x9b097d30;       (* arm_MUL X16 X9 X9 *)
  0x9b097d15;       (* arm_MUL X21 X8 X9 *)
  0x9bc87d0f;       (* arm_UMULH X15 X8 X8 *)
  0x9bc97d31;       (* arm_UMULH X17 X9 X9 *)
  0x9bc97d14;       (* arm_UMULH X20 X8 X9 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xf9404773;       (* arm_LDR X19 X27 (Immediate_Offset (word 136)) *)
  0x8b130277;       (* arm_ADD X23 X19 X19 *)
  0x9b137e73;       (* arm_MUL X19 X19 X19 *)
  0x9240cc55;       (* arm_AND X21 X2 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0x93c2d074;       (* arm_EXTR X20 X3 X2 52 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d53296;       (* arm_EXTR X22 X20 X21 12 *)
  0xab16014a;       (* arm_ADDS X10 X10 X22 *)
  0x93c3a095;       (* arm_EXTR X21 X4 X3 40 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d462b6;       (* arm_EXTR X22 X21 X20 24 *)
  0xba16016b;       (* arm_ADCS X11 X11 X22 *)
  0x93c470b4;       (* arm_EXTR X20 X5 X4 28 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d59296;       (* arm_EXTR X22 X20 X21 36 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0x93c540d5;       (* arm_EXTR X21 X6 X5 16 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d4c2b6;       (* arm_EXTR X22 X21 X20 48 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xd344fcd4;       (* arm_LSR X20 X6 4 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5f298;       (* arm_EXTR X24 X20 X21 60 *)
  0x93c6e0f5;       (* arm_EXTR X21 X7 X6 56 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd378df18;       (* arm_LSL X24 X24 8 *)
  0x93d822b6;       (* arm_EXTR X22 X21 X24 8 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0x93c7b114;       (* arm_EXTR X20 X8 X7 44 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d55296;       (* arm_EXTR X22 X20 X21 20 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0x93c88135;       (* arm_EXTR X21 X9 X8 32 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d482b6;       (* arm_EXTR X22 X21 X20 32 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xd354fd34;       (* arm_LSR X20 X9 20 *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5b296;       (* arm_EXTR X22 X20 X21 44 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0xd36cfe94;       (* arm_LSR X20 X20 44 *)
  0x9a140273;       (* arm_ADC X19 X19 X20 *)
  0x93ca2575;       (* arm_EXTR X21 X11 X10 9 *)
  0x93cb2594;       (* arm_EXTR X20 X12 X11 9 *)
  0xa904d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&72))) *)
  0x93cc25b5;       (* arm_EXTR X21 X13 X12 9 *)
  0x93cd25d4;       (* arm_EXTR X20 X14 X13 9 *)
  0xa905d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&88))) *)
  0x93ce25f5;       (* arm_EXTR X21 X15 X14 9 *)
  0x93cf2614;       (* arm_EXTR X20 X16 X15 9 *)
  0xa906d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&104))) *)
  0x93d02635;       (* arm_EXTR X21 X17 X16 9 *)
  0x93d12674;       (* arm_EXTR X20 X19 X17 9 *)
  0xa907d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&120))) *)
  0x92402156;       (* arm_AND X22 X10 (rvalue (word 511)) *)
  0xd349fe73;       (* arm_LSR X19 X19 9 *)
  0x8b1302d6;       (* arm_ADD X22 X22 X19 *)
  0xf90047f6;       (* arm_STR X22 SP (Immediate_Offset (word 136)) *)
  0x9b047c4c;       (* arm_MUL X12 X2 X4 *)
  0x9b057c71;       (* arm_MUL X17 X3 X5 *)
  0x9bc47c56;       (* arm_UMULH X22 X2 X4 *)
  0xeb030057;       (* arm_SUBS X23 X2 X3 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb0400aa;       (* arm_SUBS X10 X5 X4 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc57c77;       (* arm_UMULH X23 X3 X5 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b027c4a;       (* arm_MUL X10 X2 X2 *)
  0x9b037c70;       (* arm_MUL X16 X3 X3 *)
  0x9b037c55;       (* arm_MUL X21 X2 X3 *)
  0x9bc27c4b;       (* arm_UMULH X11 X2 X2 *)
  0x9bc37c71;       (* arm_UMULH X17 X3 X3 *)
  0x9bc37c54;       (* arm_UMULH X20 X2 X3 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b047c8e;       (* arm_MUL X14 X4 X4 *)
  0x9b057cb0;       (* arm_MUL X16 X5 X5 *)
  0x9b057c95;       (* arm_MUL X21 X4 X5 *)
  0x9bc47c8f;       (* arm_UMULH X15 X4 X4 *)
  0x9bc57cb1;       (* arm_UMULH X17 X5 X5 *)
  0x9bc57c94;       (* arm_UMULH X20 X4 X5 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xa944d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&72))) *)
  0xab0a02b5;       (* arm_ADDS X21 X21 X10 *)
  0xba0b0294;       (* arm_ADCS X20 X20 X11 *)
  0xa904d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&72))) *)
  0xa945d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&88))) *)
  0xba0c02b5;       (* arm_ADCS X21 X21 X12 *)
  0xba0d0294;       (* arm_ADCS X20 X20 X13 *)
  0xa905d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&88))) *)
  0xa946d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&104))) *)
  0xba0e02b5;       (* arm_ADCS X21 X21 X14 *)
  0xba0f0294;       (* arm_ADCS X20 X20 X15 *)
  0xa906d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&104))) *)
  0xa947d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&120))) *)
  0xba1002b5;       (* arm_ADCS X21 X21 X16 *)
  0xba110294;       (* arm_ADCS X20 X20 X17 *)
  0xa907d3f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&120))) *)
  0xf94047f6;       (* arm_LDR X22 SP (Immediate_Offset (word 136)) *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0xf90047f6;       (* arm_STR X22 SP (Immediate_Offset (word 136)) *)
  0x9b067c4a;       (* arm_MUL X10 X2 X6 *)
  0x9b077c6e;       (* arm_MUL X14 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9bc67c51;       (* arm_UMULH X17 X2 X6 *)
  0xab1101ce;       (* arm_ADDS X14 X14 X17 *)
  0x9bc77c71;       (* arm_UMULH X17 X3 X7 *)
  0xba1101ef;       (* arm_ADCS X15 X15 X17 *)
  0x9bc87c91;       (* arm_UMULH X17 X4 X8 *)
  0xba110210;       (* arm_ADCS X16 X16 X17 *)
  0x9bc97cb1;       (* arm_UMULH X17 X5 X9 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab0a01cb;       (* arm_ADDS X11 X14 X10 *)
  0xba0e01ee;       (* arm_ADCS X14 X15 X14 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xab0a01cc;       (* arm_ADDS X12 X14 X10 *)
  0xba0b01ed;       (* arm_ADCS X13 X15 X11 *)
  0xba0e020e;       (* arm_ADCS X14 X16 X14 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba1003f0;       (* arm_ADCS X16 XZR X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xeb050096;       (* arm_SUBS X22 X4 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb080134;       (* arm_SUBS X20 X9 X8 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb030056;       (* arm_SUBS X22 X2 X3 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb0600f4;       (* arm_SUBS X20 X7 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15016b;       (* arm_ADCS X11 X11 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba14018c;       (* arm_ADCS X12 X12 X20 *)
  0xba1301ad;       (* arm_ADCS X13 X13 X19 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050076;       (* arm_SUBS X22 X3 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070134;       (* arm_SUBS X20 X9 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ef;       (* arm_ADCS X15 X15 X20 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040056;       (* arm_SUBS X22 X2 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060114;       (* arm_SUBS X20 X8 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15018c;       (* arm_ADCS X12 X12 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ad;       (* arm_ADCS X13 X13 X20 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050056;       (* arm_SUBS X22 X2 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060134;       (* arm_SUBS X20 X9 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040076;       (* arm_SUBS X22 X3 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070114;       (* arm_SUBS X20 X8 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xa944d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&72))) *)
  0x93ce21e2;       (* arm_EXTR X2 X15 X14 8 *)
  0xab150042;       (* arm_ADDS X2 X2 X21 *)
  0x93cf2203;       (* arm_EXTR X3 X16 X15 8 *)
  0xba140063;       (* arm_ADCS X3 X3 X20 *)
  0xa945d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&88))) *)
  0x93d02224;       (* arm_EXTR X4 X17 X16 8 *)
  0xba150084;       (* arm_ADCS X4 X4 X21 *)
  0x8a040076;       (* arm_AND X22 X3 X4 *)
  0xd348fe25;       (* arm_LSR X5 X17 8 *)
  0xba1400a5;       (* arm_ADCS X5 X5 X20 *)
  0x8a0502d6;       (* arm_AND X22 X22 X5 *)
  0xa946d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&104))) *)
  0xd37ff946;       (* arm_LSL X6 X10 1 *)
  0xba1500c6;       (* arm_ADCS X6 X6 X21 *)
  0x8a0602d6;       (* arm_AND X22 X22 X6 *)
  0x93cafd67;       (* arm_EXTR X7 X11 X10 63 *)
  0xba1400e7;       (* arm_ADCS X7 X7 X20 *)
  0x8a0702d6;       (* arm_AND X22 X22 X7 *)
  0xa947d3f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&120))) *)
  0x93cbfd88;       (* arm_EXTR X8 X12 X11 63 *)
  0xba150108;       (* arm_ADCS X8 X8 X21 *)
  0x8a0802d6;       (* arm_AND X22 X22 X8 *)
  0x93ccfda9;       (* arm_EXTR X9 X13 X12 63 *)
  0xba140129;       (* arm_ADCS X9 X9 X20 *)
  0x8a0902d6;       (* arm_AND X22 X22 X9 *)
  0xf94047f5;       (* arm_LDR X21 SP (Immediate_Offset (word 136)) *)
  0x93cdfdca;       (* arm_EXTR X10 X14 X13 63 *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0x9a0a02aa;       (* arm_ADC X10 X21 X10 *)
  0xd349fd54;       (* arm_LSR X20 X10 9 *)
  0xb277d94a;       (* arm_ORR X10 X10 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba14005f;       (* arm_ADCS XZR X2 X20 *)
  0xba1f02df;       (* arm_ADCS XZR X22 XZR *)
  0xba1f015f;       (* arm_ADCS XZR X10 XZR *)
  0xba140042;       (* arm_ADCS X2 X2 X20 *)
  0xba1f0063;       (* arm_ADCS X3 X3 XZR *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0x9a1f014a;       (* arm_ADC X10 X10 XZR *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0xa9048fe2;       (* arm_STP X2 X3 SP (Immediate_Offset (iword (&72))) *)
  0xa90597e4;       (* arm_STP X4 X5 SP (Immediate_Offset (iword (&88))) *)
  0xa9069fe6;       (* arm_STP X6 X7 SP (Immediate_Offset (iword (&104))) *)
  0xa907a7e8;       (* arm_STP X8 X9 SP (Immediate_Offset (iword (&120))) *)
  0xf90047ea;       (* arm_STR X10 SP (Immediate_Offset (word 136)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xa9401b65;       (* arm_LDP X5 X6 X27 (Immediate_Offset (iword (&0))) *)
  0xa9400fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&0))) *)
  0xba0400a5;       (* arm_ADCS X5 X5 X4 *)
  0xba0300c6;       (* arm_ADCS X6 X6 X3 *)
  0xa9412367;       (* arm_LDP X7 X8 X27 (Immediate_Offset (iword (&16))) *)
  0xa9410fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&16))) *)
  0xba0400e7;       (* arm_ADCS X7 X7 X4 *)
  0xba030108;       (* arm_ADCS X8 X8 X3 *)
  0xa9422b69;       (* arm_LDP X9 X10 X27 (Immediate_Offset (iword (&32))) *)
  0xa9420fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&32))) *)
  0xba040129;       (* arm_ADCS X9 X9 X4 *)
  0xba03014a;       (* arm_ADCS X10 X10 X3 *)
  0xa943336b;       (* arm_LDP X11 X12 X27 (Immediate_Offset (iword (&48))) *)
  0xa9430fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&48))) *)
  0xba04016b;       (* arm_ADCS X11 X11 X4 *)
  0xba03018c;       (* arm_ADCS X12 X12 X3 *)
  0xf940236d;       (* arm_LDR X13 X27 (Immediate_Offset (word 64)) *)
  0xf94023e4;       (* arm_LDR X4 SP (Immediate_Offset (word 64)) *)
  0x9a0401ad;       (* arm_ADC X13 X13 X4 *)
  0xf10801a4;       (* arm_SUBS X4 X13 (rvalue (word 512)) *)
  0xda9f33e4;       (* arm_CSETM X4 Condition_CS *)
  0xfa1f00a5;       (* arm_SBCS X5 X5 XZR *)
  0x92770084;       (* arm_AND X4 X4 (rvalue (word 512)) *)
  0xfa1f00c6;       (* arm_SBCS X6 X6 XZR *)
  0xfa1f00e7;       (* arm_SBCS X7 X7 XZR *)
  0xfa1f0108;       (* arm_SBCS X8 X8 XZR *)
  0xfa1f0129;       (* arm_SBCS X9 X9 XZR *)
  0xfa1f014a;       (* arm_SBCS X10 X10 XZR *)
  0xfa1f016b;       (* arm_SBCS X11 X11 XZR *)
  0xfa1f018c;       (* arm_SBCS X12 X12 XZR *)
  0xda0401ad;       (* arm_SBC X13 X13 X4 *)
  0xa9169be5;       (* arm_STP X5 X6 SP (Immediate_Offset (iword (&360))) *)
  0xa917a3e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&376))) *)
  0xa918abe9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&392))) *)
  0xa919b3eb;       (* arm_STP X11 X12 SP (Immediate_Offset (iword (&408))) *)
  0xf900d7ed;       (* arm_STR X13 SP (Immediate_Offset (word 424)) *)
  0xa9401b65;       (* arm_LDP X5 X6 X27 (Immediate_Offset (iword (&0))) *)
  0xa9400fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&0))) *)
  0xeb0400a5;       (* arm_SUBS X5 X5 X4 *)
  0xfa0300c6;       (* arm_SBCS X6 X6 X3 *)
  0xa9412367;       (* arm_LDP X7 X8 X27 (Immediate_Offset (iword (&16))) *)
  0xa9410fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&16))) *)
  0xfa0400e7;       (* arm_SBCS X7 X7 X4 *)
  0xfa030108;       (* arm_SBCS X8 X8 X3 *)
  0xa9422b69;       (* arm_LDP X9 X10 X27 (Immediate_Offset (iword (&32))) *)
  0xa9420fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&32))) *)
  0xfa040129;       (* arm_SBCS X9 X9 X4 *)
  0xfa03014a;       (* arm_SBCS X10 X10 X3 *)
  0xa943336b;       (* arm_LDP X11 X12 X27 (Immediate_Offset (iword (&48))) *)
  0xa9430fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&48))) *)
  0xfa04016b;       (* arm_SBCS X11 X11 X4 *)
  0xfa03018c;       (* arm_SBCS X12 X12 X3 *)
  0xf940236d;       (* arm_LDR X13 X27 (Immediate_Offset (word 64)) *)
  0xf94023e4;       (* arm_LDR X4 SP (Immediate_Offset (word 64)) *)
  0xfa0401ad;       (* arm_SBCS X13 X13 X4 *)
  0xfa1f00a5;       (* arm_SBCS X5 X5 XZR *)
  0xfa1f00c6;       (* arm_SBCS X6 X6 XZR *)
  0xfa1f00e7;       (* arm_SBCS X7 X7 XZR *)
  0xfa1f0108;       (* arm_SBCS X8 X8 XZR *)
  0xfa1f0129;       (* arm_SBCS X9 X9 XZR *)
  0xfa1f014a;       (* arm_SBCS X10 X10 XZR *)
  0xfa1f016b;       (* arm_SBCS X11 X11 XZR *)
  0xfa1f018c;       (* arm_SBCS X12 X12 XZR *)
  0xfa1f01ad;       (* arm_SBCS X13 X13 XZR *)
  0x924021ad;       (* arm_AND X13 X13 (rvalue (word 511)) *)
  0xa9121be5;       (* arm_STP X5 X6 SP (Immediate_Offset (iword (&288))) *)
  0xa91323e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&304))) *)
  0xa9142be9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&320))) *)
  0xa91533eb;       (* arm_STP X11 X12 SP (Immediate_Offset (iword (&336))) *)
  0xf900b3ed;       (* arm_STR X13 SP (Immediate_Offset (word 352)) *)
  0xa95693e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&360))) *)
  0xa9579be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&376))) *)
  0xa95223e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&288))) *)
  0xa9532be9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&304))) *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xd377d975;       (* arm_LSL X21 X11 9 *)
  0x93cbdd8b;       (* arm_EXTR X11 X12 X11 55 *)
  0x93ccddac;       (* arm_EXTR X12 X13 X12 55 *)
  0x93cdddcd;       (* arm_EXTR X13 X14 X13 55 *)
  0xd377fdce;       (* arm_LSR X14 X14 55 *)
  0xa95893e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&392))) *)
  0xa9599be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&408))) *)
  0xa95423e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&320))) *)
  0xa9552be9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&336))) *)
  0xa90943ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&144))) *)
  0xa90a4ff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&160))) *)
  0xa90b2ff5;       (* arm_STP X21 X11 SP (Immediate_Offset (iword (&176))) *)
  0xa90c37ec;       (* arm_STP X12 X13 SP (Immediate_Offset (iword (&192))) *)
  0xf9006bee;       (* arm_STR X14 SP (Immediate_Offset (word 208)) *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xa9495bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&144))) *)
  0xab17016b;       (* arm_ADDS X11 X11 X23 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0xa90933eb;       (* arm_STP X11 X12 SP (Immediate_Offset (iword (&144))) *)
  0xa94a5bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&160))) *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xa90a3bed;       (* arm_STP X13 X14 SP (Immediate_Offset (iword (&160))) *)
  0xa94b5bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&176))) *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xa90b43ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&176))) *)
  0xa94c5bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&192))) *)
  0xba170231;       (* arm_ADCS X17 X17 X23 *)
  0xba160273;       (* arm_ADCS X19 X19 X22 *)
  0xa90c4ff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&192))) *)
  0xf9406bf5;       (* arm_LDR X21 SP (Immediate_Offset (word 208)) *)
  0x9a1f02b5;       (* arm_ADC X21 X21 XZR *)
  0xf9006bf5;       (* arm_STR X21 SP (Immediate_Offset (word 208)) *)
  0xa956dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&360))) *)
  0xeb170063;       (* arm_SUBS X3 X3 X23 *)
  0xfa160084;       (* arm_SBCS X4 X4 X22 *)
  0xa957dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&376))) *)
  0xfa1700a5;       (* arm_SBCS X5 X5 X23 *)
  0xfa1600c6;       (* arm_SBCS X6 X6 X22 *)
  0xda9f23f8;       (* arm_CSETM X24 Condition_CC *)
  0xa9525bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&288))) *)
  0xeb0702e7;       (* arm_SUBS X7 X23 X7 *)
  0xfa0802c8;       (* arm_SBCS X8 X22 X8 *)
  0xa9535bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&304))) *)
  0xfa0902e9;       (* arm_SBCS X9 X23 X9 *)
  0xfa0a02ca;       (* arm_SBCS X10 X22 X10 *)
  0xda9f23f9;       (* arm_CSETM X25 Condition_CC *)
  0xca180063;       (* arm_EOR X3 X3 X24 *)
  0xeb180063;       (* arm_SUBS X3 X3 X24 *)
  0xca180084;       (* arm_EOR X4 X4 X24 *)
  0xfa180084;       (* arm_SBCS X4 X4 X24 *)
  0xca1800a5;       (* arm_EOR X5 X5 X24 *)
  0xfa1800a5;       (* arm_SBCS X5 X5 X24 *)
  0xca1800c6;       (* arm_EOR X6 X6 X24 *)
  0xda1800c6;       (* arm_SBC X6 X6 X24 *)
  0xca1900e7;       (* arm_EOR X7 X7 X25 *)
  0xeb1900e7;       (* arm_SUBS X7 X7 X25 *)
  0xca190108;       (* arm_EOR X8 X8 X25 *)
  0xfa190108;       (* arm_SBCS X8 X8 X25 *)
  0xca190129;       (* arm_EOR X9 X9 X25 *)
  0xfa190129;       (* arm_SBCS X9 X9 X25 *)
  0xca19014a;       (* arm_EOR X10 X10 X25 *)
  0xda19014a;       (* arm_SBC X10 X10 X25 *)
  0xca180339;       (* arm_EOR X25 X25 X24 *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xa94913e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&144))) *)
  0xa94a1be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&160))) *)
  0xca19016b;       (* arm_EOR X11 X11 X25 *)
  0xab03016b;       (* arm_ADDS X11 X11 X3 *)
  0xca19018c;       (* arm_EOR X12 X12 X25 *)
  0xba04018c;       (* arm_ADCS X12 X12 X4 *)
  0xca1901ad;       (* arm_EOR X13 X13 X25 *)
  0xba0501ad;       (* arm_ADCS X13 X13 X5 *)
  0xca1901ce;       (* arm_EOR X14 X14 X25 *)
  0xba0601ce;       (* arm_ADCS X14 X14 X6 *)
  0xca1901ef;       (* arm_EOR X15 X15 X25 *)
  0xa94b23e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&176))) *)
  0xa94c2be9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&192))) *)
  0xf9406bf4;       (* arm_LDR X20 SP (Immediate_Offset (word 208)) *)
  0xba0701ef;       (* arm_ADCS X15 X15 X7 *)
  0xca190210;       (* arm_EOR X16 X16 X25 *)
  0xba080210;       (* arm_ADCS X16 X16 X8 *)
  0xca190231;       (* arm_EOR X17 X17 X25 *)
  0xba090231;       (* arm_ADCS X17 X17 X9 *)
  0xca190273;       (* arm_EOR X19 X19 X25 *)
  0xba0a0273;       (* arm_ADCS X19 X19 X10 *)
  0x9a1f0295;       (* arm_ADC X21 X20 XZR *)
  0xab0301ef;       (* arm_ADDS X15 X15 X3 *)
  0xba040210;       (* arm_ADCS X16 X16 X4 *)
  0xba050231;       (* arm_ADCS X17 X17 X5 *)
  0xba060273;       (* arm_ADCS X19 X19 X6 *)
  0x92402339;       (* arm_AND X25 X25 (rvalue (word 511)) *)
  0xd377d978;       (* arm_LSL X24 X11 9 *)
  0xaa190318;       (* arm_ORR X24 X24 X25 *)
  0xba1800e7;       (* arm_ADCS X7 X7 X24 *)
  0x93cbdd98;       (* arm_EXTR X24 X12 X11 55 *)
  0xba180108;       (* arm_ADCS X8 X8 X24 *)
  0x93ccddb8;       (* arm_EXTR X24 X13 X12 55 *)
  0xba180129;       (* arm_ADCS X9 X9 X24 *)
  0x93cdddd8;       (* arm_EXTR X24 X14 X13 55 *)
  0xba18014a;       (* arm_ADCS X10 X10 X24 *)
  0xd377fdd8;       (* arm_LSR X24 X14 55 *)
  0x9a140314;       (* arm_ADC X20 X24 X20 *)
  0xf940b3e6;       (* arm_LDR X6 SP (Immediate_Offset (word 352)) *)
  0xa95693e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&360))) *)
  0x9240cc77;       (* arm_AND X23 X3 (rvalue (word 4503599627370495)) *)
  0x9b177cd7;       (* arm_MUL X23 X6 X23 *)
  0xf940d7ee;       (* arm_LDR X14 SP (Immediate_Offset (word 424)) *)
  0xa95233eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&288))) *)
  0x9240cd78;       (* arm_AND X24 X11 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0x93c3d098;       (* arm_EXTR X24 X4 X3 52 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cbd198;       (* arm_EXTR X24 X12 X11 52 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d732d8;       (* arm_EXTR X24 X22 X23 12 *)
  0xab1801ef;       (* arm_ADDS X15 X15 X24 *)
  0xa9578fe5;       (* arm_LDP X5 X3 SP (Immediate_Offset (iword (&376))) *)
  0xa9532fed;       (* arm_LDP X13 X11 SP (Immediate_Offset (iword (&304))) *)
  0x93c4a0b8;       (* arm_EXTR X24 X5 X4 40 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cca1b8;       (* arm_EXTR X24 X13 X12 40 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d662f8;       (* arm_EXTR X24 X23 X22 24 *)
  0xba180210;       (* arm_ADCS X16 X16 X24 *)
  0x93c57078;       (* arm_EXTR X24 X3 X5 28 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cd7178;       (* arm_EXTR X24 X11 X13 28 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d792d8;       (* arm_EXTR X24 X22 X23 36 *)
  0xba180231;       (* arm_ADCS X17 X17 X24 *)
  0x8a110200;       (* arm_AND X0 X16 X17 *)
  0xa95897e4;       (* arm_LDP X4 X5 SP (Immediate_Offset (iword (&392))) *)
  0xa95437ec;       (* arm_LDP X12 X13 SP (Immediate_Offset (iword (&320))) *)
  0x93c34098;       (* arm_EXTR X24 X4 X3 16 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cb4198;       (* arm_EXTR X24 X12 X11 16 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd3503eb5;       (* arm_LSL X21 X21 48 *)
  0x8b1502f7;       (* arm_ADD X23 X23 X21 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d6c2f8;       (* arm_EXTR X24 X23 X22 48 *)
  0xba180273;       (* arm_ADCS X19 X19 X24 *)
  0x8a130000;       (* arm_AND X0 X0 X19 *)
  0xd344fc98;       (* arm_LSR X24 X4 4 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0xd344fd98;       (* arm_LSR X24 X12 4 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d7f2d9;       (* arm_EXTR X25 X22 X23 60 *)
  0x93c4e0b8;       (* arm_EXTR X24 X5 X4 56 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cce1b8;       (* arm_EXTR X24 X13 X12 56 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd378df39;       (* arm_LSL X25 X25 8 *)
  0x93d922f8;       (* arm_EXTR X24 X23 X25 8 *)
  0xba1800e7;       (* arm_ADCS X7 X7 X24 *)
  0x8a070000;       (* arm_AND X0 X0 X7 *)
  0xa95993e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&408))) *)
  0xa95533eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&336))) *)
  0x93c5b078;       (* arm_EXTR X24 X3 X5 44 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cdb178;       (* arm_EXTR X24 X11 X13 44 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d752d8;       (* arm_EXTR X24 X22 X23 20 *)
  0xba180108;       (* arm_ADCS X8 X8 X24 *)
  0x8a080000;       (* arm_AND X0 X0 X8 *)
  0x93c38098;       (* arm_EXTR X24 X4 X3 32 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cb8198;       (* arm_EXTR X24 X12 X11 32 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d682f8;       (* arm_EXTR X24 X23 X22 32 *)
  0xba180129;       (* arm_ADCS X9 X9 X24 *)
  0x8a090000;       (* arm_AND X0 X0 X9 *)
  0xd354fc98;       (* arm_LSR X24 X4 20 *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0xd354fd98;       (* arm_LSR X24 X12 20 *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d7b2d8;       (* arm_EXTR X24 X22 X23 44 *)
  0xba18014a;       (* arm_ADCS X10 X10 X24 *)
  0x8a0a0000;       (* arm_AND X0 X0 X10 *)
  0x9b0e7cd8;       (* arm_MUL X24 X6 X14 *)
  0xd36cfed6;       (* arm_LSR X22 X22 44 *)
  0x8b160318;       (* arm_ADD X24 X24 X22 *)
  0x9a180294;       (* arm_ADC X20 X20 X24 *)
  0xd349fe96;       (* arm_LSR X22 X20 9 *)
  0xb277da94;       (* arm_ORR X20 X20 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba1601ff;       (* arm_ADCS XZR X15 X22 *)
  0xba1f001f;       (* arm_ADCS XZR X0 XZR *)
  0xba1f029f;       (* arm_ADCS XZR X20 XZR *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba1f0210;       (* arm_ADCS X16 X16 XZR *)
  0xba1f0231;       (* arm_ADCS X17 X17 XZR *)
  0xba1f0273;       (* arm_ADCS X19 X19 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0xba1f014a;       (* arm_ADCS X10 X10 XZR *)
  0x9a1f0294;       (* arm_ADC X20 X20 XZR *)
  0x924021f6;       (* arm_AND X22 X15 (rvalue (word 511)) *)
  0x93cf260f;       (* arm_EXTR X15 X16 X15 9 *)
  0x93d02630;       (* arm_EXTR X16 X17 X16 9 *)
  0xa90943ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&144))) *)
  0x93d12671;       (* arm_EXTR X17 X19 X17 9 *)
  0x93d324f3;       (* arm_EXTR X19 X7 X19 9 *)
  0xa90a4ff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&160))) *)
  0x93c72507;       (* arm_EXTR X7 X8 X7 9 *)
  0x93c82528;       (* arm_EXTR X8 X9 X8 9 *)
  0xa90b23e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&176))) *)
  0x93c92549;       (* arm_EXTR X9 X10 X9 9 *)
  0x93ca268a;       (* arm_EXTR X10 X20 X10 9 *)
  0xa90c2be9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&192))) *)
  0xf9006bf6;       (* arm_STR X22 SP (Immediate_Offset (word 208)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xa9449b65;       (* arm_LDP X5 X6 X27 (Immediate_Offset (iword (&72))) *)
  0xa9490f64;       (* arm_LDP X4 X3 X27 (Immediate_Offset (iword (&144))) *)
  0xba0400a5;       (* arm_ADCS X5 X5 X4 *)
  0xba0300c6;       (* arm_ADCS X6 X6 X3 *)
  0xa945a367;       (* arm_LDP X7 X8 X27 (Immediate_Offset (iword (&88))) *)
  0xa94a0f64;       (* arm_LDP X4 X3 X27 (Immediate_Offset (iword (&160))) *)
  0xba0400e7;       (* arm_ADCS X7 X7 X4 *)
  0xba030108;       (* arm_ADCS X8 X8 X3 *)
  0xa946ab69;       (* arm_LDP X9 X10 X27 (Immediate_Offset (iword (&104))) *)
  0xa94b0f64;       (* arm_LDP X4 X3 X27 (Immediate_Offset (iword (&176))) *)
  0xba040129;       (* arm_ADCS X9 X9 X4 *)
  0xba03014a;       (* arm_ADCS X10 X10 X3 *)
  0xa947b36b;       (* arm_LDP X11 X12 X27 (Immediate_Offset (iword (&120))) *)
  0xa94c0f64;       (* arm_LDP X4 X3 X27 (Immediate_Offset (iword (&192))) *)
  0xba04016b;       (* arm_ADCS X11 X11 X4 *)
  0xba03018c;       (* arm_ADCS X12 X12 X3 *)
  0xf940476d;       (* arm_LDR X13 X27 (Immediate_Offset (word 136)) *)
  0xf9406b64;       (* arm_LDR X4 X27 (Immediate_Offset (word 208)) *)
  0x9a0401ad;       (* arm_ADC X13 X13 X4 *)
  0xf10801a4;       (* arm_SUBS X4 X13 (rvalue (word 512)) *)
  0xda9f33e4;       (* arm_CSETM X4 Condition_CS *)
  0xfa1f00a5;       (* arm_SBCS X5 X5 XZR *)
  0x92770084;       (* arm_AND X4 X4 (rvalue (word 512)) *)
  0xfa1f00c6;       (* arm_SBCS X6 X6 XZR *)
  0xfa1f00e7;       (* arm_SBCS X7 X7 XZR *)
  0xfa1f0108;       (* arm_SBCS X8 X8 XZR *)
  0xfa1f0129;       (* arm_SBCS X9 X9 XZR *)
  0xfa1f014a;       (* arm_SBCS X10 X10 XZR *)
  0xfa1f016b;       (* arm_SBCS X11 X11 XZR *)
  0xfa1f018c;       (* arm_SBCS X12 X12 XZR *)
  0xda0401ad;       (* arm_SBC X13 X13 X4 *)
  0xa9169be5;       (* arm_STP X5 X6 SP (Immediate_Offset (iword (&360))) *)
  0xa917a3e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&376))) *)
  0xa918abe9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&392))) *)
  0xa919b3eb;       (* arm_STP X11 X12 SP (Immediate_Offset (iword (&408))) *)
  0xf900d7ed;       (* arm_STR X13 SP (Immediate_Offset (word 424)) *)
  0xa9490fe2;       (* arm_LDP X2 X3 SP (Immediate_Offset (iword (&144))) *)
  0xa94a17e4;       (* arm_LDP X4 X5 SP (Immediate_Offset (iword (&160))) *)
  0xa94b1fe6;       (* arm_LDP X6 X7 SP (Immediate_Offset (iword (&176))) *)
  0xa94c27e8;       (* arm_LDP X8 X9 SP (Immediate_Offset (iword (&192))) *)
  0x9b087ccc;       (* arm_MUL X12 X6 X8 *)
  0x9b097cf1;       (* arm_MUL X17 X7 X9 *)
  0x9bc87cd6;       (* arm_UMULH X22 X6 X8 *)
  0xeb0700d7;       (* arm_SUBS X23 X6 X7 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb08012a;       (* arm_SUBS X10 X9 X8 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc97cf7;       (* arm_UMULH X23 X7 X9 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b067cca;       (* arm_MUL X10 X6 X6 *)
  0x9b077cf0;       (* arm_MUL X16 X7 X7 *)
  0x9b077cd5;       (* arm_MUL X21 X6 X7 *)
  0x9bc67ccb;       (* arm_UMULH X11 X6 X6 *)
  0x9bc77cf1;       (* arm_UMULH X17 X7 X7 *)
  0x9bc77cd4;       (* arm_UMULH X20 X6 X7 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b087d0e;       (* arm_MUL X14 X8 X8 *)
  0x9b097d30;       (* arm_MUL X16 X9 X9 *)
  0x9b097d15;       (* arm_MUL X21 X8 X9 *)
  0x9bc87d0f;       (* arm_UMULH X15 X8 X8 *)
  0x9bc97d31;       (* arm_UMULH X17 X9 X9 *)
  0x9bc97d14;       (* arm_UMULH X20 X8 X9 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xf9406bf3;       (* arm_LDR X19 SP (Immediate_Offset (word 208)) *)
  0x8b130277;       (* arm_ADD X23 X19 X19 *)
  0x9b137e73;       (* arm_MUL X19 X19 X19 *)
  0x9240cc55;       (* arm_AND X21 X2 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0x93c2d074;       (* arm_EXTR X20 X3 X2 52 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d53296;       (* arm_EXTR X22 X20 X21 12 *)
  0xab16014a;       (* arm_ADDS X10 X10 X22 *)
  0x93c3a095;       (* arm_EXTR X21 X4 X3 40 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d462b6;       (* arm_EXTR X22 X21 X20 24 *)
  0xba16016b;       (* arm_ADCS X11 X11 X22 *)
  0x93c470b4;       (* arm_EXTR X20 X5 X4 28 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d59296;       (* arm_EXTR X22 X20 X21 36 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0x93c540d5;       (* arm_EXTR X21 X6 X5 16 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d4c2b6;       (* arm_EXTR X22 X21 X20 48 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xd344fcd4;       (* arm_LSR X20 X6 4 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5f298;       (* arm_EXTR X24 X20 X21 60 *)
  0x93c6e0f5;       (* arm_EXTR X21 X7 X6 56 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd378df18;       (* arm_LSL X24 X24 8 *)
  0x93d822b6;       (* arm_EXTR X22 X21 X24 8 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0x93c7b114;       (* arm_EXTR X20 X8 X7 44 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d55296;       (* arm_EXTR X22 X20 X21 20 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0x93c88135;       (* arm_EXTR X21 X9 X8 32 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d482b6;       (* arm_EXTR X22 X21 X20 32 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xd354fd34;       (* arm_LSR X20 X9 20 *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5b296;       (* arm_EXTR X22 X20 X21 44 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0xd36cfe94;       (* arm_LSR X20 X20 44 *)
  0x9a140273;       (* arm_ADC X19 X19 X20 *)
  0x93ca2575;       (* arm_EXTR X21 X11 X10 9 *)
  0x93cb2594;       (* arm_EXTR X20 X12 X11 9 *)
  0xa91b53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&432))) *)
  0x93cc25b5;       (* arm_EXTR X21 X13 X12 9 *)
  0x93cd25d4;       (* arm_EXTR X20 X14 X13 9 *)
  0xa91c53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&448))) *)
  0x93ce25f5;       (* arm_EXTR X21 X15 X14 9 *)
  0x93cf2614;       (* arm_EXTR X20 X16 X15 9 *)
  0xa91d53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&464))) *)
  0x93d02635;       (* arm_EXTR X21 X17 X16 9 *)
  0x93d12674;       (* arm_EXTR X20 X19 X17 9 *)
  0xa91e53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&480))) *)
  0x92402156;       (* arm_AND X22 X10 (rvalue (word 511)) *)
  0xd349fe73;       (* arm_LSR X19 X19 9 *)
  0x8b1302d6;       (* arm_ADD X22 X22 X19 *)
  0xf900fbf6;       (* arm_STR X22 SP (Immediate_Offset (word 496)) *)
  0x9b047c4c;       (* arm_MUL X12 X2 X4 *)
  0x9b057c71;       (* arm_MUL X17 X3 X5 *)
  0x9bc47c56;       (* arm_UMULH X22 X2 X4 *)
  0xeb030057;       (* arm_SUBS X23 X2 X3 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb0400aa;       (* arm_SUBS X10 X5 X4 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc57c77;       (* arm_UMULH X23 X3 X5 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b027c4a;       (* arm_MUL X10 X2 X2 *)
  0x9b037c70;       (* arm_MUL X16 X3 X3 *)
  0x9b037c55;       (* arm_MUL X21 X2 X3 *)
  0x9bc27c4b;       (* arm_UMULH X11 X2 X2 *)
  0x9bc37c71;       (* arm_UMULH X17 X3 X3 *)
  0x9bc37c54;       (* arm_UMULH X20 X2 X3 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b047c8e;       (* arm_MUL X14 X4 X4 *)
  0x9b057cb0;       (* arm_MUL X16 X5 X5 *)
  0x9b057c95;       (* arm_MUL X21 X4 X5 *)
  0x9bc47c8f;       (* arm_UMULH X15 X4 X4 *)
  0x9bc57cb1;       (* arm_UMULH X17 X5 X5 *)
  0x9bc57c94;       (* arm_UMULH X20 X4 X5 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xa95b53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&432))) *)
  0xab0a02b5;       (* arm_ADDS X21 X21 X10 *)
  0xba0b0294;       (* arm_ADCS X20 X20 X11 *)
  0xa91b53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&432))) *)
  0xa95c53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&448))) *)
  0xba0c02b5;       (* arm_ADCS X21 X21 X12 *)
  0xba0d0294;       (* arm_ADCS X20 X20 X13 *)
  0xa91c53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&448))) *)
  0xa95d53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&464))) *)
  0xba0e02b5;       (* arm_ADCS X21 X21 X14 *)
  0xba0f0294;       (* arm_ADCS X20 X20 X15 *)
  0xa91d53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&464))) *)
  0xa95e53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&480))) *)
  0xba1002b5;       (* arm_ADCS X21 X21 X16 *)
  0xba110294;       (* arm_ADCS X20 X20 X17 *)
  0xa91e53f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&480))) *)
  0xf940fbf6;       (* arm_LDR X22 SP (Immediate_Offset (word 496)) *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0xf900fbf6;       (* arm_STR X22 SP (Immediate_Offset (word 496)) *)
  0x9b067c4a;       (* arm_MUL X10 X2 X6 *)
  0x9b077c6e;       (* arm_MUL X14 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9bc67c51;       (* arm_UMULH X17 X2 X6 *)
  0xab1101ce;       (* arm_ADDS X14 X14 X17 *)
  0x9bc77c71;       (* arm_UMULH X17 X3 X7 *)
  0xba1101ef;       (* arm_ADCS X15 X15 X17 *)
  0x9bc87c91;       (* arm_UMULH X17 X4 X8 *)
  0xba110210;       (* arm_ADCS X16 X16 X17 *)
  0x9bc97cb1;       (* arm_UMULH X17 X5 X9 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab0a01cb;       (* arm_ADDS X11 X14 X10 *)
  0xba0e01ee;       (* arm_ADCS X14 X15 X14 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xab0a01cc;       (* arm_ADDS X12 X14 X10 *)
  0xba0b01ed;       (* arm_ADCS X13 X15 X11 *)
  0xba0e020e;       (* arm_ADCS X14 X16 X14 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba1003f0;       (* arm_ADCS X16 XZR X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xeb050096;       (* arm_SUBS X22 X4 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb080134;       (* arm_SUBS X20 X9 X8 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb030056;       (* arm_SUBS X22 X2 X3 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb0600f4;       (* arm_SUBS X20 X7 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15016b;       (* arm_ADCS X11 X11 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba14018c;       (* arm_ADCS X12 X12 X20 *)
  0xba1301ad;       (* arm_ADCS X13 X13 X19 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050076;       (* arm_SUBS X22 X3 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070134;       (* arm_SUBS X20 X9 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ef;       (* arm_ADCS X15 X15 X20 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040056;       (* arm_SUBS X22 X2 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060114;       (* arm_SUBS X20 X8 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15018c;       (* arm_ADCS X12 X12 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ad;       (* arm_ADCS X13 X13 X20 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050056;       (* arm_SUBS X22 X2 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060134;       (* arm_SUBS X20 X9 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040076;       (* arm_SUBS X22 X3 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070114;       (* arm_SUBS X20 X8 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xa95b53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&432))) *)
  0x93ce21e2;       (* arm_EXTR X2 X15 X14 8 *)
  0xab150042;       (* arm_ADDS X2 X2 X21 *)
  0x93cf2203;       (* arm_EXTR X3 X16 X15 8 *)
  0xba140063;       (* arm_ADCS X3 X3 X20 *)
  0xa95c53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&448))) *)
  0x93d02224;       (* arm_EXTR X4 X17 X16 8 *)
  0xba150084;       (* arm_ADCS X4 X4 X21 *)
  0x8a040076;       (* arm_AND X22 X3 X4 *)
  0xd348fe25;       (* arm_LSR X5 X17 8 *)
  0xba1400a5;       (* arm_ADCS X5 X5 X20 *)
  0x8a0502d6;       (* arm_AND X22 X22 X5 *)
  0xa95d53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&464))) *)
  0xd37ff946;       (* arm_LSL X6 X10 1 *)
  0xba1500c6;       (* arm_ADCS X6 X6 X21 *)
  0x8a0602d6;       (* arm_AND X22 X22 X6 *)
  0x93cafd67;       (* arm_EXTR X7 X11 X10 63 *)
  0xba1400e7;       (* arm_ADCS X7 X7 X20 *)
  0x8a0702d6;       (* arm_AND X22 X22 X7 *)
  0xa95e53f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&480))) *)
  0x93cbfd88;       (* arm_EXTR X8 X12 X11 63 *)
  0xba150108;       (* arm_ADCS X8 X8 X21 *)
  0x8a0802d6;       (* arm_AND X22 X22 X8 *)
  0x93ccfda9;       (* arm_EXTR X9 X13 X12 63 *)
  0xba140129;       (* arm_ADCS X9 X9 X20 *)
  0x8a0902d6;       (* arm_AND X22 X22 X9 *)
  0xf940fbf5;       (* arm_LDR X21 SP (Immediate_Offset (word 496)) *)
  0x93cdfdca;       (* arm_EXTR X10 X14 X13 63 *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0x9a0a02aa;       (* arm_ADC X10 X21 X10 *)
  0xd349fd54;       (* arm_LSR X20 X10 9 *)
  0xb277d94a;       (* arm_ORR X10 X10 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba14005f;       (* arm_ADCS XZR X2 X20 *)
  0xba1f02df;       (* arm_ADCS XZR X22 XZR *)
  0xba1f015f;       (* arm_ADCS XZR X10 XZR *)
  0xba140042;       (* arm_ADCS X2 X2 X20 *)
  0xba1f0063;       (* arm_ADCS X3 X3 XZR *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0x9a1f014a;       (* arm_ADC X10 X10 XZR *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0xa91b0fe2;       (* arm_STP X2 X3 SP (Immediate_Offset (iword (&432))) *)
  0xa91c17e4;       (* arm_STP X4 X5 SP (Immediate_Offset (iword (&448))) *)
  0xa91d1fe6;       (* arm_STP X6 X7 SP (Immediate_Offset (iword (&464))) *)
  0xa91e27e8;       (* arm_STP X8 X9 SP (Immediate_Offset (iword (&480))) *)
  0xf900fbea;       (* arm_STR X10 SP (Immediate_Offset (word 496)) *)
  0xa9401363;       (* arm_LDP X3 X4 X27 (Immediate_Offset (iword (&0))) *)
  0xa9411b65;       (* arm_LDP X5 X6 X27 (Immediate_Offset (iword (&16))) *)
  0xa944a3e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&72))) *)
  0xa945abe9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&88))) *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xd377d975;       (* arm_LSL X21 X11 9 *)
  0x93cbdd8b;       (* arm_EXTR X11 X12 X11 55 *)
  0x93ccddac;       (* arm_EXTR X12 X13 X12 55 *)
  0x93cdddcd;       (* arm_EXTR X13 X14 X13 55 *)
  0xd377fdce;       (* arm_LSR X14 X14 55 *)
  0xa9421363;       (* arm_LDP X3 X4 X27 (Immediate_Offset (iword (&32))) *)
  0xa9431b65;       (* arm_LDP X5 X6 X27 (Immediate_Offset (iword (&48))) *)
  0xa946a3e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&104))) *)
  0xa947abe9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&120))) *)
  0xa90dc3ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&216))) *)
  0xa90ecff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&232))) *)
  0xa90faff5;       (* arm_STP X21 X11 SP (Immediate_Offset (iword (&248))) *)
  0xa910b7ec;       (* arm_STP X12 X13 SP (Immediate_Offset (iword (&264))) *)
  0xf9008fee;       (* arm_STR X14 SP (Immediate_Offset (word 280)) *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xa94ddbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&216))) *)
  0xab17016b;       (* arm_ADDS X11 X11 X23 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0xa90db3eb;       (* arm_STP X11 X12 SP (Immediate_Offset (iword (&216))) *)
  0xa94edbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&232))) *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xa90ebbed;       (* arm_STP X13 X14 SP (Immediate_Offset (iword (&232))) *)
  0xa94fdbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&248))) *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xa90fc3ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&248))) *)
  0xa950dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&264))) *)
  0xba170231;       (* arm_ADCS X17 X17 X23 *)
  0xba160273;       (* arm_ADCS X19 X19 X22 *)
  0xa910cff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&264))) *)
  0xf9408ff5;       (* arm_LDR X21 SP (Immediate_Offset (word 280)) *)
  0x9a1f02b5;       (* arm_ADC X21 X21 XZR *)
  0xf9008ff5;       (* arm_STR X21 SP (Immediate_Offset (word 280)) *)
  0xa9405b77;       (* arm_LDP X23 X22 X27 (Immediate_Offset (iword (&0))) *)
  0xeb170063;       (* arm_SUBS X3 X3 X23 *)
  0xfa160084;       (* arm_SBCS X4 X4 X22 *)
  0xa9415b77;       (* arm_LDP X23 X22 X27 (Immediate_Offset (iword (&16))) *)
  0xfa1700a5;       (* arm_SBCS X5 X5 X23 *)
  0xfa1600c6;       (* arm_SBCS X6 X6 X22 *)
  0xda9f23f8;       (* arm_CSETM X24 Condition_CC *)
  0xa944dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&72))) *)
  0xeb0702e7;       (* arm_SUBS X7 X23 X7 *)
  0xfa0802c8;       (* arm_SBCS X8 X22 X8 *)
  0xa945dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&88))) *)
  0xfa0902e9;       (* arm_SBCS X9 X23 X9 *)
  0xfa0a02ca;       (* arm_SBCS X10 X22 X10 *)
  0xda9f23f9;       (* arm_CSETM X25 Condition_CC *)
  0xca180063;       (* arm_EOR X3 X3 X24 *)
  0xeb180063;       (* arm_SUBS X3 X3 X24 *)
  0xca180084;       (* arm_EOR X4 X4 X24 *)
  0xfa180084;       (* arm_SBCS X4 X4 X24 *)
  0xca1800a5;       (* arm_EOR X5 X5 X24 *)
  0xfa1800a5;       (* arm_SBCS X5 X5 X24 *)
  0xca1800c6;       (* arm_EOR X6 X6 X24 *)
  0xda1800c6;       (* arm_SBC X6 X6 X24 *)
  0xca1900e7;       (* arm_EOR X7 X7 X25 *)
  0xeb1900e7;       (* arm_SUBS X7 X7 X25 *)
  0xca190108;       (* arm_EOR X8 X8 X25 *)
  0xfa190108;       (* arm_SBCS X8 X8 X25 *)
  0xca190129;       (* arm_EOR X9 X9 X25 *)
  0xfa190129;       (* arm_SBCS X9 X9 X25 *)
  0xca19014a;       (* arm_EOR X10 X10 X25 *)
  0xda19014a;       (* arm_SBC X10 X10 X25 *)
  0xca180339;       (* arm_EOR X25 X25 X24 *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xa94d93e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&216))) *)
  0xa94e9be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&232))) *)
  0xca19016b;       (* arm_EOR X11 X11 X25 *)
  0xab03016b;       (* arm_ADDS X11 X11 X3 *)
  0xca19018c;       (* arm_EOR X12 X12 X25 *)
  0xba04018c;       (* arm_ADCS X12 X12 X4 *)
  0xca1901ad;       (* arm_EOR X13 X13 X25 *)
  0xba0501ad;       (* arm_ADCS X13 X13 X5 *)
  0xca1901ce;       (* arm_EOR X14 X14 X25 *)
  0xba0601ce;       (* arm_ADCS X14 X14 X6 *)
  0xca1901ef;       (* arm_EOR X15 X15 X25 *)
  0xa94fa3e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&248))) *)
  0xa950abe9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&264))) *)
  0xf9408ff4;       (* arm_LDR X20 SP (Immediate_Offset (word 280)) *)
  0xba0701ef;       (* arm_ADCS X15 X15 X7 *)
  0xca190210;       (* arm_EOR X16 X16 X25 *)
  0xba080210;       (* arm_ADCS X16 X16 X8 *)
  0xca190231;       (* arm_EOR X17 X17 X25 *)
  0xba090231;       (* arm_ADCS X17 X17 X9 *)
  0xca190273;       (* arm_EOR X19 X19 X25 *)
  0xba0a0273;       (* arm_ADCS X19 X19 X10 *)
  0x9a1f0295;       (* arm_ADC X21 X20 XZR *)
  0xab0301ef;       (* arm_ADDS X15 X15 X3 *)
  0xba040210;       (* arm_ADCS X16 X16 X4 *)
  0xba050231;       (* arm_ADCS X17 X17 X5 *)
  0xba060273;       (* arm_ADCS X19 X19 X6 *)
  0x92402339;       (* arm_AND X25 X25 (rvalue (word 511)) *)
  0xd377d978;       (* arm_LSL X24 X11 9 *)
  0xaa190318;       (* arm_ORR X24 X24 X25 *)
  0xba1800e7;       (* arm_ADCS X7 X7 X24 *)
  0x93cbdd98;       (* arm_EXTR X24 X12 X11 55 *)
  0xba180108;       (* arm_ADCS X8 X8 X24 *)
  0x93ccddb8;       (* arm_EXTR X24 X13 X12 55 *)
  0xba180129;       (* arm_ADCS X9 X9 X24 *)
  0x93cdddd8;       (* arm_EXTR X24 X14 X13 55 *)
  0xba18014a;       (* arm_ADCS X10 X10 X24 *)
  0xd377fdd8;       (* arm_LSR X24 X14 55 *)
  0x9a140314;       (* arm_ADC X20 X24 X20 *)
  0xf94047e6;       (* arm_LDR X6 SP (Immediate_Offset (word 136)) *)
  0xa9401363;       (* arm_LDP X3 X4 X27 (Immediate_Offset (iword (&0))) *)
  0x9240cc77;       (* arm_AND X23 X3 (rvalue (word 4503599627370495)) *)
  0x9b177cd7;       (* arm_MUL X23 X6 X23 *)
  0xf940236e;       (* arm_LDR X14 X27 (Immediate_Offset (word 64)) *)
  0xa944b3eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&72))) *)
  0x9240cd78;       (* arm_AND X24 X11 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0x93c3d098;       (* arm_EXTR X24 X4 X3 52 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cbd198;       (* arm_EXTR X24 X12 X11 52 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d732d8;       (* arm_EXTR X24 X22 X23 12 *)
  0xab1801ef;       (* arm_ADDS X15 X15 X24 *)
  0xa9410f65;       (* arm_LDP X5 X3 X27 (Immediate_Offset (iword (&16))) *)
  0xa945afed;       (* arm_LDP X13 X11 SP (Immediate_Offset (iword (&88))) *)
  0x93c4a0b8;       (* arm_EXTR X24 X5 X4 40 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cca1b8;       (* arm_EXTR X24 X13 X12 40 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d662f8;       (* arm_EXTR X24 X23 X22 24 *)
  0xba180210;       (* arm_ADCS X16 X16 X24 *)
  0x93c57078;       (* arm_EXTR X24 X3 X5 28 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cd7178;       (* arm_EXTR X24 X11 X13 28 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d792d8;       (* arm_EXTR X24 X22 X23 36 *)
  0xba180231;       (* arm_ADCS X17 X17 X24 *)
  0x8a110200;       (* arm_AND X0 X16 X17 *)
  0xa9421764;       (* arm_LDP X4 X5 X27 (Immediate_Offset (iword (&32))) *)
  0xa946b7ec;       (* arm_LDP X12 X13 SP (Immediate_Offset (iword (&104))) *)
  0x93c34098;       (* arm_EXTR X24 X4 X3 16 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cb4198;       (* arm_EXTR X24 X12 X11 16 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd3503eb5;       (* arm_LSL X21 X21 48 *)
  0x8b1502f7;       (* arm_ADD X23 X23 X21 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d6c2f8;       (* arm_EXTR X24 X23 X22 48 *)
  0xba180273;       (* arm_ADCS X19 X19 X24 *)
  0x8a130000;       (* arm_AND X0 X0 X19 *)
  0xd344fc98;       (* arm_LSR X24 X4 4 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0xd344fd98;       (* arm_LSR X24 X12 4 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d7f2d9;       (* arm_EXTR X25 X22 X23 60 *)
  0x93c4e0b8;       (* arm_EXTR X24 X5 X4 56 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cce1b8;       (* arm_EXTR X24 X13 X12 56 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd378df39;       (* arm_LSL X25 X25 8 *)
  0x93d922f8;       (* arm_EXTR X24 X23 X25 8 *)
  0xba1800e7;       (* arm_ADCS X7 X7 X24 *)
  0x8a070000;       (* arm_AND X0 X0 X7 *)
  0xa9431363;       (* arm_LDP X3 X4 X27 (Immediate_Offset (iword (&48))) *)
  0xa947b3eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&120))) *)
  0x93c5b078;       (* arm_EXTR X24 X3 X5 44 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cdb178;       (* arm_EXTR X24 X11 X13 44 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d752d8;       (* arm_EXTR X24 X22 X23 20 *)
  0xba180108;       (* arm_ADCS X8 X8 X24 *)
  0x8a080000;       (* arm_AND X0 X0 X8 *)
  0x93c38098;       (* arm_EXTR X24 X4 X3 32 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cb8198;       (* arm_EXTR X24 X12 X11 32 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d682f8;       (* arm_EXTR X24 X23 X22 32 *)
  0xba180129;       (* arm_ADCS X9 X9 X24 *)
  0x8a090000;       (* arm_AND X0 X0 X9 *)
  0xd354fc98;       (* arm_LSR X24 X4 20 *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0xd354fd98;       (* arm_LSR X24 X12 20 *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d7b2d8;       (* arm_EXTR X24 X22 X23 44 *)
  0xba18014a;       (* arm_ADCS X10 X10 X24 *)
  0x8a0a0000;       (* arm_AND X0 X0 X10 *)
  0x9b0e7cd8;       (* arm_MUL X24 X6 X14 *)
  0xd36cfed6;       (* arm_LSR X22 X22 44 *)
  0x8b160318;       (* arm_ADD X24 X24 X22 *)
  0x9a180294;       (* arm_ADC X20 X20 X24 *)
  0xd349fe96;       (* arm_LSR X22 X20 9 *)
  0xb277da94;       (* arm_ORR X20 X20 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba1601ff;       (* arm_ADCS XZR X15 X22 *)
  0xba1f001f;       (* arm_ADCS XZR X0 XZR *)
  0xba1f029f;       (* arm_ADCS XZR X20 XZR *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba1f0210;       (* arm_ADCS X16 X16 XZR *)
  0xba1f0231;       (* arm_ADCS X17 X17 XZR *)
  0xba1f0273;       (* arm_ADCS X19 X19 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0xba1f014a;       (* arm_ADCS X10 X10 XZR *)
  0x9a1f0294;       (* arm_ADC X20 X20 XZR *)
  0x924021f6;       (* arm_AND X22 X15 (rvalue (word 511)) *)
  0x93cf260f;       (* arm_EXTR X15 X16 X15 9 *)
  0x93d02630;       (* arm_EXTR X16 X17 X16 9 *)
  0xa90dc3ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&216))) *)
  0x93d12671;       (* arm_EXTR X17 X19 X17 9 *)
  0x93d324f3;       (* arm_EXTR X19 X7 X19 9 *)
  0xa90ecff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&232))) *)
  0x93c72507;       (* arm_EXTR X7 X8 X7 9 *)
  0x93c82528;       (* arm_EXTR X8 X9 X8 9 *)
  0xa90fa3e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&248))) *)
  0x93c92549;       (* arm_EXTR X9 X10 X9 9 *)
  0x93ca268a;       (* arm_EXTR X10 X20 X10 9 *)
  0xa910abe9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&264))) *)
  0xf9008ff6;       (* arm_STR X22 SP (Immediate_Offset (word 280)) *)
  0xa9568fe2;       (* arm_LDP X2 X3 SP (Immediate_Offset (iword (&360))) *)
  0xa95797e4;       (* arm_LDP X4 X5 SP (Immediate_Offset (iword (&376))) *)
  0xa9589fe6;       (* arm_LDP X6 X7 SP (Immediate_Offset (iword (&392))) *)
  0xa959a7e8;       (* arm_LDP X8 X9 SP (Immediate_Offset (iword (&408))) *)
  0x9b087ccc;       (* arm_MUL X12 X6 X8 *)
  0x9b097cf1;       (* arm_MUL X17 X7 X9 *)
  0x9bc87cd6;       (* arm_UMULH X22 X6 X8 *)
  0xeb0700d7;       (* arm_SUBS X23 X6 X7 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb08012a;       (* arm_SUBS X10 X9 X8 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc97cf7;       (* arm_UMULH X23 X7 X9 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b067cca;       (* arm_MUL X10 X6 X6 *)
  0x9b077cf0;       (* arm_MUL X16 X7 X7 *)
  0x9b077cd5;       (* arm_MUL X21 X6 X7 *)
  0x9bc67ccb;       (* arm_UMULH X11 X6 X6 *)
  0x9bc77cf1;       (* arm_UMULH X17 X7 X7 *)
  0x9bc77cd4;       (* arm_UMULH X20 X6 X7 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b087d0e;       (* arm_MUL X14 X8 X8 *)
  0x9b097d30;       (* arm_MUL X16 X9 X9 *)
  0x9b097d15;       (* arm_MUL X21 X8 X9 *)
  0x9bc87d0f;       (* arm_UMULH X15 X8 X8 *)
  0x9bc97d31;       (* arm_UMULH X17 X9 X9 *)
  0x9bc97d14;       (* arm_UMULH X20 X8 X9 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xf940d7f3;       (* arm_LDR X19 SP (Immediate_Offset (word 424)) *)
  0x8b130277;       (* arm_ADD X23 X19 X19 *)
  0x9b137e73;       (* arm_MUL X19 X19 X19 *)
  0x9240cc55;       (* arm_AND X21 X2 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0x93c2d074;       (* arm_EXTR X20 X3 X2 52 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d53296;       (* arm_EXTR X22 X20 X21 12 *)
  0xab16014a;       (* arm_ADDS X10 X10 X22 *)
  0x93c3a095;       (* arm_EXTR X21 X4 X3 40 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d462b6;       (* arm_EXTR X22 X21 X20 24 *)
  0xba16016b;       (* arm_ADCS X11 X11 X22 *)
  0x93c470b4;       (* arm_EXTR X20 X5 X4 28 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d59296;       (* arm_EXTR X22 X20 X21 36 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0x93c540d5;       (* arm_EXTR X21 X6 X5 16 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d4c2b6;       (* arm_EXTR X22 X21 X20 48 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xd344fcd4;       (* arm_LSR X20 X6 4 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5f298;       (* arm_EXTR X24 X20 X21 60 *)
  0x93c6e0f5;       (* arm_EXTR X21 X7 X6 56 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd378df18;       (* arm_LSL X24 X24 8 *)
  0x93d822b6;       (* arm_EXTR X22 X21 X24 8 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0x93c7b114;       (* arm_EXTR X20 X8 X7 44 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d55296;       (* arm_EXTR X22 X20 X21 20 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0x93c88135;       (* arm_EXTR X21 X9 X8 32 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d482b6;       (* arm_EXTR X22 X21 X20 32 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xd354fd34;       (* arm_LSR X20 X9 20 *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5b296;       (* arm_EXTR X22 X20 X21 44 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0xd36cfe94;       (* arm_LSR X20 X20 44 *)
  0x9a140273;       (* arm_ADC X19 X19 X20 *)
  0x93ca2575;       (* arm_EXTR X21 X11 X10 9 *)
  0x93cb2594;       (* arm_EXTR X20 X12 X11 9 *)
  0xa91253f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0x93cc25b5;       (* arm_EXTR X21 X13 X12 9 *)
  0x93cd25d4;       (* arm_EXTR X20 X14 X13 9 *)
  0xa91353f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0x93ce25f5;       (* arm_EXTR X21 X15 X14 9 *)
  0x93cf2614;       (* arm_EXTR X20 X16 X15 9 *)
  0xa91453f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0x93d02635;       (* arm_EXTR X21 X17 X16 9 *)
  0x93d12674;       (* arm_EXTR X20 X19 X17 9 *)
  0xa91553f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0x92402156;       (* arm_AND X22 X10 (rvalue (word 511)) *)
  0xd349fe73;       (* arm_LSR X19 X19 9 *)
  0x8b1302d6;       (* arm_ADD X22 X22 X19 *)
  0xf900b3f6;       (* arm_STR X22 SP (Immediate_Offset (word 352)) *)
  0x9b047c4c;       (* arm_MUL X12 X2 X4 *)
  0x9b057c71;       (* arm_MUL X17 X3 X5 *)
  0x9bc47c56;       (* arm_UMULH X22 X2 X4 *)
  0xeb030057;       (* arm_SUBS X23 X2 X3 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb0400aa;       (* arm_SUBS X10 X5 X4 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc57c77;       (* arm_UMULH X23 X3 X5 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b027c4a;       (* arm_MUL X10 X2 X2 *)
  0x9b037c70;       (* arm_MUL X16 X3 X3 *)
  0x9b037c55;       (* arm_MUL X21 X2 X3 *)
  0x9bc27c4b;       (* arm_UMULH X11 X2 X2 *)
  0x9bc37c71;       (* arm_UMULH X17 X3 X3 *)
  0x9bc37c54;       (* arm_UMULH X20 X2 X3 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b047c8e;       (* arm_MUL X14 X4 X4 *)
  0x9b057cb0;       (* arm_MUL X16 X5 X5 *)
  0x9b057c95;       (* arm_MUL X21 X4 X5 *)
  0x9bc47c8f;       (* arm_UMULH X15 X4 X4 *)
  0x9bc57cb1;       (* arm_UMULH X17 X5 X5 *)
  0x9bc57c94;       (* arm_UMULH X20 X4 X5 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xa95253f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0xab0a02b5;       (* arm_ADDS X21 X21 X10 *)
  0xba0b0294;       (* arm_ADCS X20 X20 X11 *)
  0xa91253f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0xa95353f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0xba0c02b5;       (* arm_ADCS X21 X21 X12 *)
  0xba0d0294;       (* arm_ADCS X20 X20 X13 *)
  0xa91353f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0xa95453f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0xba0e02b5;       (* arm_ADCS X21 X21 X14 *)
  0xba0f0294;       (* arm_ADCS X20 X20 X15 *)
  0xa91453f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0xa95553f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0xba1002b5;       (* arm_ADCS X21 X21 X16 *)
  0xba110294;       (* arm_ADCS X20 X20 X17 *)
  0xa91553f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0xf940b3f6;       (* arm_LDR X22 SP (Immediate_Offset (word 352)) *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0xf900b3f6;       (* arm_STR X22 SP (Immediate_Offset (word 352)) *)
  0x9b067c4a;       (* arm_MUL X10 X2 X6 *)
  0x9b077c6e;       (* arm_MUL X14 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9bc67c51;       (* arm_UMULH X17 X2 X6 *)
  0xab1101ce;       (* arm_ADDS X14 X14 X17 *)
  0x9bc77c71;       (* arm_UMULH X17 X3 X7 *)
  0xba1101ef;       (* arm_ADCS X15 X15 X17 *)
  0x9bc87c91;       (* arm_UMULH X17 X4 X8 *)
  0xba110210;       (* arm_ADCS X16 X16 X17 *)
  0x9bc97cb1;       (* arm_UMULH X17 X5 X9 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab0a01cb;       (* arm_ADDS X11 X14 X10 *)
  0xba0e01ee;       (* arm_ADCS X14 X15 X14 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xab0a01cc;       (* arm_ADDS X12 X14 X10 *)
  0xba0b01ed;       (* arm_ADCS X13 X15 X11 *)
  0xba0e020e;       (* arm_ADCS X14 X16 X14 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba1003f0;       (* arm_ADCS X16 XZR X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xeb050096;       (* arm_SUBS X22 X4 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb080134;       (* arm_SUBS X20 X9 X8 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb030056;       (* arm_SUBS X22 X2 X3 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb0600f4;       (* arm_SUBS X20 X7 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15016b;       (* arm_ADCS X11 X11 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba14018c;       (* arm_ADCS X12 X12 X20 *)
  0xba1301ad;       (* arm_ADCS X13 X13 X19 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050076;       (* arm_SUBS X22 X3 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070134;       (* arm_SUBS X20 X9 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ef;       (* arm_ADCS X15 X15 X20 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040056;       (* arm_SUBS X22 X2 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060114;       (* arm_SUBS X20 X8 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15018c;       (* arm_ADCS X12 X12 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ad;       (* arm_ADCS X13 X13 X20 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050056;       (* arm_SUBS X22 X2 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060134;       (* arm_SUBS X20 X9 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040076;       (* arm_SUBS X22 X3 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070114;       (* arm_SUBS X20 X8 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xa95253f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0x93ce21e2;       (* arm_EXTR X2 X15 X14 8 *)
  0xab150042;       (* arm_ADDS X2 X2 X21 *)
  0x93cf2203;       (* arm_EXTR X3 X16 X15 8 *)
  0xba140063;       (* arm_ADCS X3 X3 X20 *)
  0xa95353f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0x93d02224;       (* arm_EXTR X4 X17 X16 8 *)
  0xba150084;       (* arm_ADCS X4 X4 X21 *)
  0x8a040076;       (* arm_AND X22 X3 X4 *)
  0xd348fe25;       (* arm_LSR X5 X17 8 *)
  0xba1400a5;       (* arm_ADCS X5 X5 X20 *)
  0x8a0502d6;       (* arm_AND X22 X22 X5 *)
  0xa95453f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0xd37ff946;       (* arm_LSL X6 X10 1 *)
  0xba1500c6;       (* arm_ADCS X6 X6 X21 *)
  0x8a0602d6;       (* arm_AND X22 X22 X6 *)
  0x93cafd67;       (* arm_EXTR X7 X11 X10 63 *)
  0xba1400e7;       (* arm_ADCS X7 X7 X20 *)
  0x8a0702d6;       (* arm_AND X22 X22 X7 *)
  0xa95553f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0x93cbfd88;       (* arm_EXTR X8 X12 X11 63 *)
  0xba150108;       (* arm_ADCS X8 X8 X21 *)
  0x8a0802d6;       (* arm_AND X22 X22 X8 *)
  0x93ccfda9;       (* arm_EXTR X9 X13 X12 63 *)
  0xba140129;       (* arm_ADCS X9 X9 X20 *)
  0x8a0902d6;       (* arm_AND X22 X22 X9 *)
  0xf940b3f5;       (* arm_LDR X21 SP (Immediate_Offset (word 352)) *)
  0x93cdfdca;       (* arm_EXTR X10 X14 X13 63 *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0x9a0a02aa;       (* arm_ADC X10 X21 X10 *)
  0xd349fd54;       (* arm_LSR X20 X10 9 *)
  0xb277d94a;       (* arm_ORR X10 X10 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba14005f;       (* arm_ADCS XZR X2 X20 *)
  0xba1f02df;       (* arm_ADCS XZR X22 XZR *)
  0xba1f015f;       (* arm_ADCS XZR X10 XZR *)
  0xba140042;       (* arm_ADCS X2 X2 X20 *)
  0xba1f0063;       (* arm_ADCS X3 X3 XZR *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0x9a1f014a;       (* arm_ADC X10 X10 XZR *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0xa9120fe2;       (* arm_STP X2 X3 SP (Immediate_Offset (iword (&288))) *)
  0xa91317e4;       (* arm_STP X4 X5 SP (Immediate_Offset (iword (&304))) *)
  0xa9141fe6;       (* arm_STP X6 X7 SP (Immediate_Offset (iword (&320))) *)
  0xa91527e8;       (* arm_STP X8 X9 SP (Immediate_Offset (iword (&336))) *)
  0xf900b3ea;       (* arm_STR X10 SP (Immediate_Offset (word 352)) *)
  0xa94d9fe6;       (* arm_LDP X6 X7 SP (Immediate_Offset (iword (&216))) *)
  0xd2800181;       (* arm_MOV X1 (rvalue (word 12)) *)
  0x9b067c23;       (* arm_MUL X3 X1 X6 *)
  0x9b077c24;       (* arm_MUL X4 X1 X7 *)
  0x9bc67c26;       (* arm_UMULH X6 X1 X6 *)
  0xab060084;       (* arm_ADDS X4 X4 X6 *)
  0x9bc77c27;       (* arm_UMULH X7 X1 X7 *)
  0xa94ea7e8;       (* arm_LDP X8 X9 SP (Immediate_Offset (iword (&232))) *)
  0x9b087c25;       (* arm_MUL X5 X1 X8 *)
  0x9b097c26;       (* arm_MUL X6 X1 X9 *)
  0x9bc87c28;       (* arm_UMULH X8 X1 X8 *)
  0xba0700a5;       (* arm_ADCS X5 X5 X7 *)
  0x9bc97c29;       (* arm_UMULH X9 X1 X9 *)
  0xba0800c6;       (* arm_ADCS X6 X6 X8 *)
  0xa94fafea;       (* arm_LDP X10 X11 SP (Immediate_Offset (iword (&248))) *)
  0x9b0a7c27;       (* arm_MUL X7 X1 X10 *)
  0x9b0b7c28;       (* arm_MUL X8 X1 X11 *)
  0x9bca7c2a;       (* arm_UMULH X10 X1 X10 *)
  0xba0900e7;       (* arm_ADCS X7 X7 X9 *)
  0x9bcb7c2b;       (* arm_UMULH X11 X1 X11 *)
  0xba0a0108;       (* arm_ADCS X8 X8 X10 *)
  0xa950b7ec;       (* arm_LDP X12 X13 SP (Immediate_Offset (iword (&264))) *)
  0x9b0c7c29;       (* arm_MUL X9 X1 X12 *)
  0x9b0d7c2a;       (* arm_MUL X10 X1 X13 *)
  0x9bcc7c2c;       (* arm_UMULH X12 X1 X12 *)
  0xba0b0129;       (* arm_ADCS X9 X9 X11 *)
  0x9bcd7c2d;       (* arm_UMULH X13 X1 X13 *)
  0xba0c014a;       (* arm_ADCS X10 X10 X12 *)
  0xf9408fee;       (* arm_LDR X14 SP (Immediate_Offset (word 280)) *)
  0x9b0e7c2b;       (* arm_MUL X11 X1 X14 *)
  0x9a0d016b;       (* arm_ADC X11 X11 X13 *)
  0xd2800121;       (* arm_MOV X1 (rvalue (word 9)) *)
  0xa95b57f4;       (* arm_LDP X20 X21 SP (Immediate_Offset (iword (&432))) *)
  0xaa3403f4;       (* arm_MVN X20 X20 *)
  0x9b147c20;       (* arm_MUL X0 X1 X20 *)
  0x9bd47c34;       (* arm_UMULH X20 X1 X20 *)
  0xab000063;       (* arm_ADDS X3 X3 X0 *)
  0xaa3503f5;       (* arm_MVN X21 X21 *)
  0x9b157c20;       (* arm_MUL X0 X1 X21 *)
  0x9bd57c35;       (* arm_UMULH X21 X1 X21 *)
  0xba000084;       (* arm_ADCS X4 X4 X0 *)
  0xa95c5ff6;       (* arm_LDP X22 X23 SP (Immediate_Offset (iword (&448))) *)
  0xaa3603f6;       (* arm_MVN X22 X22 *)
  0x9b167c20;       (* arm_MUL X0 X1 X22 *)
  0x9bd67c36;       (* arm_UMULH X22 X1 X22 *)
  0xba0000a5;       (* arm_ADCS X5 X5 X0 *)
  0xaa3703f7;       (* arm_MVN X23 X23 *)
  0x9b177c20;       (* arm_MUL X0 X1 X23 *)
  0x9bd77c37;       (* arm_UMULH X23 X1 X23 *)
  0xba0000c6;       (* arm_ADCS X6 X6 X0 *)
  0xa95d4ff1;       (* arm_LDP X17 X19 SP (Immediate_Offset (iword (&464))) *)
  0xaa3103f1;       (* arm_MVN X17 X17 *)
  0x9b117c20;       (* arm_MUL X0 X1 X17 *)
  0x9bd17c31;       (* arm_UMULH X17 X1 X17 *)
  0xba0000e7;       (* arm_ADCS X7 X7 X0 *)
  0xaa3303f3;       (* arm_MVN X19 X19 *)
  0x9b137c20;       (* arm_MUL X0 X1 X19 *)
  0x9bd37c33;       (* arm_UMULH X19 X1 X19 *)
  0xba000108;       (* arm_ADCS X8 X8 X0 *)
  0xa95e43e2;       (* arm_LDP X2 X16 SP (Immediate_Offset (iword (&480))) *)
  0xaa2203e2;       (* arm_MVN X2 X2 *)
  0x9b027c20;       (* arm_MUL X0 X1 X2 *)
  0x9bc27c22;       (* arm_UMULH X2 X1 X2 *)
  0xba000129;       (* arm_ADCS X9 X9 X0 *)
  0xaa3003f0;       (* arm_MVN X16 X16 *)
  0x9b107c20;       (* arm_MUL X0 X1 X16 *)
  0x9bd07c30;       (* arm_UMULH X16 X1 X16 *)
  0xba00014a;       (* arm_ADCS X10 X10 X0 *)
  0xf940fbe0;       (* arm_LDR X0 SP (Immediate_Offset (word 496)) *)
  0xd2402000;       (* arm_EOR X0 X0 (rvalue (word 511)) *)
  0x9b007c20;       (* arm_MUL X0 X1 X0 *)
  0x9a00016b;       (* arm_ADC X11 X11 X0 *)
  0xab140084;       (* arm_ADDS X4 X4 X20 *)
  0xba1500a5;       (* arm_ADCS X5 X5 X21 *)
  0x8a05008f;       (* arm_AND X15 X4 X5 *)
  0xba1600c6;       (* arm_ADCS X6 X6 X22 *)
  0x8a0601ef;       (* arm_AND X15 X15 X6 *)
  0xba1700e7;       (* arm_ADCS X7 X7 X23 *)
  0x8a0701ef;       (* arm_AND X15 X15 X7 *)
  0xba110108;       (* arm_ADCS X8 X8 X17 *)
  0x8a0801ef;       (* arm_AND X15 X15 X8 *)
  0xba130129;       (* arm_ADCS X9 X9 X19 *)
  0x8a0901ef;       (* arm_AND X15 X15 X9 *)
  0xba02014a;       (* arm_ADCS X10 X10 X2 *)
  0x8a0a01ef;       (* arm_AND X15 X15 X10 *)
  0x9a10016b;       (* arm_ADC X11 X11 X16 *)
  0xd349fd6c;       (* arm_LSR X12 X11 9 *)
  0xb277d96b;       (* arm_ORR X11 X11 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba0c007f;       (* arm_ADCS XZR X3 X12 *)
  0xba1f01ff;       (* arm_ADCS XZR X15 XZR *)
  0xba1f017f;       (* arm_ADCS XZR X11 XZR *)
  0xba0c0063;       (* arm_ADCS X3 X3 X12 *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0xba1f014a;       (* arm_ADCS X10 X10 XZR *)
  0x9a1f016b;       (* arm_ADC X11 X11 XZR *)
  0x9240216b;       (* arm_AND X11 X11 (rvalue (word 511)) *)
  0xa91b13e3;       (* arm_STP X3 X4 SP (Immediate_Offset (iword (&432))) *)
  0xa91c1be5;       (* arm_STP X5 X6 SP (Immediate_Offset (iword (&448))) *)
  0xa91d23e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&464))) *)
  0xa91e2be9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&480))) *)
  0xf900fbeb;       (* arm_STR X11 SP (Immediate_Offset (word 496)) *)
  0xa9521be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&288))) *)
  0xa9400fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&0))) *)
  0xeb0400a5;       (* arm_SUBS X5 X5 X4 *)
  0xfa0300c6;       (* arm_SBCS X6 X6 X3 *)
  0xa95323e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&304))) *)
  0xa9410fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&16))) *)
  0xfa0400e7;       (* arm_SBCS X7 X7 X4 *)
  0xfa030108;       (* arm_SBCS X8 X8 X3 *)
  0xa9542be9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&320))) *)
  0xa9420fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&32))) *)
  0xfa040129;       (* arm_SBCS X9 X9 X4 *)
  0xfa03014a;       (* arm_SBCS X10 X10 X3 *)
  0xa95533eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&336))) *)
  0xa9430fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&48))) *)
  0xfa04016b;       (* arm_SBCS X11 X11 X4 *)
  0xfa03018c;       (* arm_SBCS X12 X12 X3 *)
  0xf940b3ed;       (* arm_LDR X13 SP (Immediate_Offset (word 352)) *)
  0xf94023e4;       (* arm_LDR X4 SP (Immediate_Offset (word 64)) *)
  0xfa0401ad;       (* arm_SBCS X13 X13 X4 *)
  0xfa1f00a5;       (* arm_SBCS X5 X5 XZR *)
  0xfa1f00c6;       (* arm_SBCS X6 X6 XZR *)
  0xfa1f00e7;       (* arm_SBCS X7 X7 XZR *)
  0xfa1f0108;       (* arm_SBCS X8 X8 XZR *)
  0xfa1f0129;       (* arm_SBCS X9 X9 XZR *)
  0xfa1f014a;       (* arm_SBCS X10 X10 XZR *)
  0xfa1f016b;       (* arm_SBCS X11 X11 XZR *)
  0xfa1f018c;       (* arm_SBCS X12 X12 XZR *)
  0xfa1f01ad;       (* arm_SBCS X13 X13 XZR *)
  0x924021ad;       (* arm_AND X13 X13 (rvalue (word 511)) *)
  0xa9169be5;       (* arm_STP X5 X6 SP (Immediate_Offset (iword (&360))) *)
  0xa917a3e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&376))) *)
  0xa918abe9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&392))) *)
  0xa919b3eb;       (* arm_STP X11 X12 SP (Immediate_Offset (iword (&408))) *)
  0xf900d7ed;       (* arm_STR X13 SP (Immediate_Offset (word 424)) *)
  0xa9448fe2;       (* arm_LDP X2 X3 SP (Immediate_Offset (iword (&72))) *)
  0xa94597e4;       (* arm_LDP X4 X5 SP (Immediate_Offset (iword (&88))) *)
  0xa9469fe6;       (* arm_LDP X6 X7 SP (Immediate_Offset (iword (&104))) *)
  0xa947a7e8;       (* arm_LDP X8 X9 SP (Immediate_Offset (iword (&120))) *)
  0x9b087ccc;       (* arm_MUL X12 X6 X8 *)
  0x9b097cf1;       (* arm_MUL X17 X7 X9 *)
  0x9bc87cd6;       (* arm_UMULH X22 X6 X8 *)
  0xeb0700d7;       (* arm_SUBS X23 X6 X7 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb08012a;       (* arm_SUBS X10 X9 X8 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc97cf7;       (* arm_UMULH X23 X7 X9 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b067cca;       (* arm_MUL X10 X6 X6 *)
  0x9b077cf0;       (* arm_MUL X16 X7 X7 *)
  0x9b077cd5;       (* arm_MUL X21 X6 X7 *)
  0x9bc67ccb;       (* arm_UMULH X11 X6 X6 *)
  0x9bc77cf1;       (* arm_UMULH X17 X7 X7 *)
  0x9bc77cd4;       (* arm_UMULH X20 X6 X7 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b087d0e;       (* arm_MUL X14 X8 X8 *)
  0x9b097d30;       (* arm_MUL X16 X9 X9 *)
  0x9b097d15;       (* arm_MUL X21 X8 X9 *)
  0x9bc87d0f;       (* arm_UMULH X15 X8 X8 *)
  0x9bc97d31;       (* arm_UMULH X17 X9 X9 *)
  0x9bc97d14;       (* arm_UMULH X20 X8 X9 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xf94047f3;       (* arm_LDR X19 SP (Immediate_Offset (word 136)) *)
  0x8b130277;       (* arm_ADD X23 X19 X19 *)
  0x9b137e73;       (* arm_MUL X19 X19 X19 *)
  0x9240cc55;       (* arm_AND X21 X2 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0x93c2d074;       (* arm_EXTR X20 X3 X2 52 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d53296;       (* arm_EXTR X22 X20 X21 12 *)
  0xab16014a;       (* arm_ADDS X10 X10 X22 *)
  0x93c3a095;       (* arm_EXTR X21 X4 X3 40 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d462b6;       (* arm_EXTR X22 X21 X20 24 *)
  0xba16016b;       (* arm_ADCS X11 X11 X22 *)
  0x93c470b4;       (* arm_EXTR X20 X5 X4 28 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d59296;       (* arm_EXTR X22 X20 X21 36 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0x93c540d5;       (* arm_EXTR X21 X6 X5 16 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d4c2b6;       (* arm_EXTR X22 X21 X20 48 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xd344fcd4;       (* arm_LSR X20 X6 4 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5f298;       (* arm_EXTR X24 X20 X21 60 *)
  0x93c6e0f5;       (* arm_EXTR X21 X7 X6 56 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd378df18;       (* arm_LSL X24 X24 8 *)
  0x93d822b6;       (* arm_EXTR X22 X21 X24 8 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0x93c7b114;       (* arm_EXTR X20 X8 X7 44 *)
  0x9240ce94;       (* arm_AND X20 X20 (rvalue (word 4503599627370495)) *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d55296;       (* arm_EXTR X22 X20 X21 20 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0x93c88135;       (* arm_EXTR X21 X9 X8 32 *)
  0x9240ceb5;       (* arm_AND X21 X21 (rvalue (word 4503599627370495)) *)
  0x9b157ef5;       (* arm_MUL X21 X23 X21 *)
  0xd374fe96;       (* arm_LSR X22 X20 52 *)
  0x8b1602b5;       (* arm_ADD X21 X21 X22 *)
  0xd374ce94;       (* arm_LSL X20 X20 12 *)
  0x93d482b6;       (* arm_EXTR X22 X21 X20 32 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xd354fd34;       (* arm_LSR X20 X9 20 *)
  0x9b147ef4;       (* arm_MUL X20 X23 X20 *)
  0xd374feb6;       (* arm_LSR X22 X21 52 *)
  0x8b160294;       (* arm_ADD X20 X20 X22 *)
  0xd374ceb5;       (* arm_LSL X21 X21 12 *)
  0x93d5b296;       (* arm_EXTR X22 X20 X21 44 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0xd36cfe94;       (* arm_LSR X20 X20 44 *)
  0x9a140273;       (* arm_ADC X19 X19 X20 *)
  0x93ca2575;       (* arm_EXTR X21 X11 X10 9 *)
  0x93cb2594;       (* arm_EXTR X20 X12 X11 9 *)
  0xa91253f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0x93cc25b5;       (* arm_EXTR X21 X13 X12 9 *)
  0x93cd25d4;       (* arm_EXTR X20 X14 X13 9 *)
  0xa91353f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0x93ce25f5;       (* arm_EXTR X21 X15 X14 9 *)
  0x93cf2614;       (* arm_EXTR X20 X16 X15 9 *)
  0xa91453f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0x93d02635;       (* arm_EXTR X21 X17 X16 9 *)
  0x93d12674;       (* arm_EXTR X20 X19 X17 9 *)
  0xa91553f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0x92402156;       (* arm_AND X22 X10 (rvalue (word 511)) *)
  0xd349fe73;       (* arm_LSR X19 X19 9 *)
  0x8b1302d6;       (* arm_ADD X22 X22 X19 *)
  0xf900b3f6;       (* arm_STR X22 SP (Immediate_Offset (word 352)) *)
  0x9b047c4c;       (* arm_MUL X12 X2 X4 *)
  0x9b057c71;       (* arm_MUL X17 X3 X5 *)
  0x9bc47c56;       (* arm_UMULH X22 X2 X4 *)
  0xeb030057;       (* arm_SUBS X23 X2 X3 *)
  0xda9726f7;       (* arm_CNEG X23 X23 Condition_CC *)
  0xda9f23eb;       (* arm_CSETM X11 Condition_CC *)
  0xeb0400aa;       (* arm_SUBS X10 X5 X4 *)
  0xda8a254a;       (* arm_CNEG X10 X10 Condition_CC *)
  0x9b0a7ef0;       (* arm_MUL X16 X23 X10 *)
  0x9bca7eea;       (* arm_UMULH X10 X23 X10 *)
  0xda8b216b;       (* arm_CINV X11 X11 Condition_CC *)
  0xca0b0210;       (* arm_EOR X16 X16 X11 *)
  0xca0b014a;       (* arm_EOR X10 X10 X11 *)
  0xab16018d;       (* arm_ADDS X13 X12 X22 *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0x9bc57c77;       (* arm_UMULH X23 X3 X5 *)
  0xab1101ad;       (* arm_ADDS X13 X13 X17 *)
  0xba1702d6;       (* arm_ADCS X22 X22 X23 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xab1102d6;       (* arm_ADDS X22 X22 X17 *)
  0x9a1f02f7;       (* arm_ADC X23 X23 XZR *)
  0xb100057f;       (* arm_CMN X11 (rvalue (word 1)) *)
  0xba1001ad;       (* arm_ADCS X13 X13 X16 *)
  0xba0a02d6;       (* arm_ADCS X22 X22 X10 *)
  0x9a0b02f7;       (* arm_ADC X23 X23 X11 *)
  0xab0c018c;       (* arm_ADDS X12 X12 X12 *)
  0xba0d01ad;       (* arm_ADCS X13 X13 X13 *)
  0xba1602d6;       (* arm_ADCS X22 X22 X22 *)
  0xba1702f7;       (* arm_ADCS X23 X23 X23 *)
  0x9a1f03f3;       (* arm_ADC X19 XZR XZR *)
  0x9b027c4a;       (* arm_MUL X10 X2 X2 *)
  0x9b037c70;       (* arm_MUL X16 X3 X3 *)
  0x9b037c55;       (* arm_MUL X21 X2 X3 *)
  0x9bc27c4b;       (* arm_UMULH X11 X2 X2 *)
  0x9bc37c71;       (* arm_UMULH X17 X3 X3 *)
  0x9bc37c54;       (* arm_UMULH X20 X2 X3 *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab15016b;       (* arm_ADDS X11 X11 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab10018c;       (* arm_ADDS X12 X12 X16 *)
  0xba1101ad;       (* arm_ADCS X13 X13 X17 *)
  0xba1f02d6;       (* arm_ADCS X22 X22 XZR *)
  0xba1f02f7;       (* arm_ADCS X23 X23 XZR *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0x9b047c8e;       (* arm_MUL X14 X4 X4 *)
  0x9b057cb0;       (* arm_MUL X16 X5 X5 *)
  0x9b057c95;       (* arm_MUL X21 X4 X5 *)
  0x9bc47c8f;       (* arm_UMULH X15 X4 X4 *)
  0x9bc57cb1;       (* arm_UMULH X17 X5 X5 *)
  0x9bc57c94;       (* arm_UMULH X20 X4 X5 *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1501ef;       (* arm_ADDS X15 X15 X21 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab1601ce;       (* arm_ADDS X14 X14 X22 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xa95253f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0xab0a02b5;       (* arm_ADDS X21 X21 X10 *)
  0xba0b0294;       (* arm_ADCS X20 X20 X11 *)
  0xa91253f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0xa95353f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0xba0c02b5;       (* arm_ADCS X21 X21 X12 *)
  0xba0d0294;       (* arm_ADCS X20 X20 X13 *)
  0xa91353f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0xa95453f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0xba0e02b5;       (* arm_ADCS X21 X21 X14 *)
  0xba0f0294;       (* arm_ADCS X20 X20 X15 *)
  0xa91453f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0xa95553f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0xba1002b5;       (* arm_ADCS X21 X21 X16 *)
  0xba110294;       (* arm_ADCS X20 X20 X17 *)
  0xa91553f5;       (* arm_STP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0xf940b3f6;       (* arm_LDR X22 SP (Immediate_Offset (word 352)) *)
  0x9a1f02d6;       (* arm_ADC X22 X22 XZR *)
  0xf900b3f6;       (* arm_STR X22 SP (Immediate_Offset (word 352)) *)
  0x9b067c4a;       (* arm_MUL X10 X2 X6 *)
  0x9b077c6e;       (* arm_MUL X14 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9bc67c51;       (* arm_UMULH X17 X2 X6 *)
  0xab1101ce;       (* arm_ADDS X14 X14 X17 *)
  0x9bc77c71;       (* arm_UMULH X17 X3 X7 *)
  0xba1101ef;       (* arm_ADCS X15 X15 X17 *)
  0x9bc87c91;       (* arm_UMULH X17 X4 X8 *)
  0xba110210;       (* arm_ADCS X16 X16 X17 *)
  0x9bc97cb1;       (* arm_UMULH X17 X5 X9 *)
  0x9a1f0231;       (* arm_ADC X17 X17 XZR *)
  0xab0a01cb;       (* arm_ADDS X11 X14 X10 *)
  0xba0e01ee;       (* arm_ADCS X14 X15 X14 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xab0a01cc;       (* arm_ADDS X12 X14 X10 *)
  0xba0b01ed;       (* arm_ADCS X13 X15 X11 *)
  0xba0e020e;       (* arm_ADCS X14 X16 X14 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba1003f0;       (* arm_ADCS X16 XZR X16 *)
  0x9a1103f1;       (* arm_ADC X17 XZR X17 *)
  0xeb050096;       (* arm_SUBS X22 X4 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb080134;       (* arm_SUBS X20 X9 X8 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba140210;       (* arm_ADCS X16 X16 X20 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb030056;       (* arm_SUBS X22 X2 X3 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb0600f4;       (* arm_SUBS X20 X7 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15016b;       (* arm_ADCS X11 X11 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba14018c;       (* arm_ADCS X12 X12 X20 *)
  0xba1301ad;       (* arm_ADCS X13 X13 X19 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050076;       (* arm_SUBS X22 X3 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070134;       (* arm_SUBS X20 X9 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ef;       (* arm_ADCS X15 X15 X20 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040056;       (* arm_SUBS X22 X2 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060114;       (* arm_SUBS X20 X8 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba15018c;       (* arm_ADCS X12 X12 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ad;       (* arm_ADCS X13 X13 X20 *)
  0xba1301ce;       (* arm_ADCS X14 X14 X19 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb050056;       (* arm_SUBS X22 X2 X5 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb060134;       (* arm_SUBS X20 X9 X6 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xeb040076;       (* arm_SUBS X22 X3 X4 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0xda9f23f3;       (* arm_CSETM X19 Condition_CC *)
  0xeb070114;       (* arm_SUBS X20 X8 X7 *)
  0xda942694;       (* arm_CNEG X20 X20 Condition_CC *)
  0x9b147ed5;       (* arm_MUL X21 X22 X20 *)
  0x9bd47ed4;       (* arm_UMULH X20 X22 X20 *)
  0xda932273;       (* arm_CINV X19 X19 Condition_CC *)
  0xb100067f;       (* arm_CMN X19 (rvalue (word 1)) *)
  0xca1302b5;       (* arm_EOR X21 X21 X19 *)
  0xba1501ad;       (* arm_ADCS X13 X13 X21 *)
  0xca130294;       (* arm_EOR X20 X20 X19 *)
  0xba1401ce;       (* arm_ADCS X14 X14 X20 *)
  0xba1301ef;       (* arm_ADCS X15 X15 X19 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9a130231;       (* arm_ADC X17 X17 X19 *)
  0xa95253f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&288))) *)
  0x93ce21e2;       (* arm_EXTR X2 X15 X14 8 *)
  0xab150042;       (* arm_ADDS X2 X2 X21 *)
  0x93cf2203;       (* arm_EXTR X3 X16 X15 8 *)
  0xba140063;       (* arm_ADCS X3 X3 X20 *)
  0xa95353f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&304))) *)
  0x93d02224;       (* arm_EXTR X4 X17 X16 8 *)
  0xba150084;       (* arm_ADCS X4 X4 X21 *)
  0x8a040076;       (* arm_AND X22 X3 X4 *)
  0xd348fe25;       (* arm_LSR X5 X17 8 *)
  0xba1400a5;       (* arm_ADCS X5 X5 X20 *)
  0x8a0502d6;       (* arm_AND X22 X22 X5 *)
  0xa95453f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&320))) *)
  0xd37ff946;       (* arm_LSL X6 X10 1 *)
  0xba1500c6;       (* arm_ADCS X6 X6 X21 *)
  0x8a0602d6;       (* arm_AND X22 X22 X6 *)
  0x93cafd67;       (* arm_EXTR X7 X11 X10 63 *)
  0xba1400e7;       (* arm_ADCS X7 X7 X20 *)
  0x8a0702d6;       (* arm_AND X22 X22 X7 *)
  0xa95553f5;       (* arm_LDP X21 X20 SP (Immediate_Offset (iword (&336))) *)
  0x93cbfd88;       (* arm_EXTR X8 X12 X11 63 *)
  0xba150108;       (* arm_ADCS X8 X8 X21 *)
  0x8a0802d6;       (* arm_AND X22 X22 X8 *)
  0x93ccfda9;       (* arm_EXTR X9 X13 X12 63 *)
  0xba140129;       (* arm_ADCS X9 X9 X20 *)
  0x8a0902d6;       (* arm_AND X22 X22 X9 *)
  0xf940b3f5;       (* arm_LDR X21 SP (Immediate_Offset (word 352)) *)
  0x93cdfdca;       (* arm_EXTR X10 X14 X13 63 *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0x9a0a02aa;       (* arm_ADC X10 X21 X10 *)
  0xd349fd54;       (* arm_LSR X20 X10 9 *)
  0xb277d94a;       (* arm_ORR X10 X10 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba14005f;       (* arm_ADCS XZR X2 X20 *)
  0xba1f02df;       (* arm_ADCS XZR X22 XZR *)
  0xba1f015f;       (* arm_ADCS XZR X10 XZR *)
  0xba140042;       (* arm_ADCS X2 X2 X20 *)
  0xba1f0063;       (* arm_ADCS X3 X3 XZR *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0x9a1f014a;       (* arm_ADC X10 X10 XZR *)
  0x9240214a;       (* arm_AND X10 X10 (rvalue (word 511)) *)
  0xa9120fe2;       (* arm_STP X2 X3 SP (Immediate_Offset (iword (&288))) *)
  0xa91317e4;       (* arm_STP X4 X5 SP (Immediate_Offset (iword (&304))) *)
  0xa9141fe6;       (* arm_STP X6 X7 SP (Immediate_Offset (iword (&320))) *)
  0xa91527e8;       (* arm_STP X8 X9 SP (Immediate_Offset (iword (&336))) *)
  0xf900b3ea;       (* arm_STR X10 SP (Immediate_Offset (word 352)) *)
  0xa9569be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&360))) *)
  0xa9448fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&72))) *)
  0xeb0400a5;       (* arm_SUBS X5 X5 X4 *)
  0xfa0300c6;       (* arm_SBCS X6 X6 X3 *)
  0xa957a3e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&376))) *)
  0xa9458fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&88))) *)
  0xfa0400e7;       (* arm_SBCS X7 X7 X4 *)
  0xfa030108;       (* arm_SBCS X8 X8 X3 *)
  0xa958abe9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&392))) *)
  0xa9468fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&104))) *)
  0xfa040129;       (* arm_SBCS X9 X9 X4 *)
  0xfa03014a;       (* arm_SBCS X10 X10 X3 *)
  0xa959b3eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&408))) *)
  0xa9478fe4;       (* arm_LDP X4 X3 SP (Immediate_Offset (iword (&120))) *)
  0xfa04016b;       (* arm_SBCS X11 X11 X4 *)
  0xfa03018c;       (* arm_SBCS X12 X12 X3 *)
  0xf940d7ed;       (* arm_LDR X13 SP (Immediate_Offset (word 424)) *)
  0xf94047e4;       (* arm_LDR X4 SP (Immediate_Offset (word 136)) *)
  0xfa0401ad;       (* arm_SBCS X13 X13 X4 *)
  0xfa1f00a5;       (* arm_SBCS X5 X5 XZR *)
  0xfa1f00c6;       (* arm_SBCS X6 X6 XZR *)
  0xfa1f00e7;       (* arm_SBCS X7 X7 XZR *)
  0xfa1f0108;       (* arm_SBCS X8 X8 XZR *)
  0xfa1f0129;       (* arm_SBCS X9 X9 XZR *)
  0xfa1f014a;       (* arm_SBCS X10 X10 XZR *)
  0xfa1f016b;       (* arm_SBCS X11 X11 XZR *)
  0xfa1f018c;       (* arm_SBCS X12 X12 XZR *)
  0xfa1f01ad;       (* arm_SBCS X13 X13 XZR *)
  0x924021ad;       (* arm_AND X13 X13 (rvalue (word 511)) *)
  0xa9091b45;       (* arm_STP X5 X6 X26 (Immediate_Offset (iword (&144))) *)
  0xa90a2347;       (* arm_STP X7 X8 X26 (Immediate_Offset (iword (&160))) *)
  0xa90b2b49;       (* arm_STP X9 X10 X26 (Immediate_Offset (iword (&176))) *)
  0xa90c334b;       (* arm_STP X11 X12 X26 (Immediate_Offset (iword (&192))) *)
  0xf9006b4d;       (* arm_STR X13 X26 (Immediate_Offset (word 208)) *)
  0xa95b13e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&432))) *)
  0xa95c1be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&448))) *)
  0xa94923e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&144))) *)
  0xa94a2be9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&160))) *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xd377d975;       (* arm_LSL X21 X11 9 *)
  0x93cbdd8b;       (* arm_EXTR X11 X12 X11 55 *)
  0x93ccddac;       (* arm_EXTR X12 X13 X12 55 *)
  0x93cdddcd;       (* arm_EXTR X13 X14 X13 55 *)
  0xd377fdce;       (* arm_LSR X14 X14 55 *)
  0xa95d13e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&464))) *)
  0xa95e1be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&480))) *)
  0xa94b23e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&176))) *)
  0xa94c2be9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&192))) *)
  0xa916c3ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&360))) *)
  0xa917cff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&376))) *)
  0xa918aff5;       (* arm_STP X21 X11 SP (Immediate_Offset (iword (&392))) *)
  0xa919b7ec;       (* arm_STP X12 X13 SP (Immediate_Offset (iword (&408))) *)
  0xf900d7ee;       (* arm_STR X14 SP (Immediate_Offset (word 424)) *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xa956dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&360))) *)
  0xab17016b;       (* arm_ADDS X11 X11 X23 *)
  0xba16018c;       (* arm_ADCS X12 X12 X22 *)
  0xa916b3eb;       (* arm_STP X11 X12 SP (Immediate_Offset (iword (&360))) *)
  0xa957dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&376))) *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xa917bbed;       (* arm_STP X13 X14 SP (Immediate_Offset (iword (&376))) *)
  0xa958dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&392))) *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xa918c3ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&392))) *)
  0xa959dbf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&408))) *)
  0xba170231;       (* arm_ADCS X17 X17 X23 *)
  0xba160273;       (* arm_ADCS X19 X19 X22 *)
  0xa919cff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&408))) *)
  0xf940d7f5;       (* arm_LDR X21 SP (Immediate_Offset (word 424)) *)
  0x9a1f02b5;       (* arm_ADC X21 X21 XZR *)
  0xf900d7f5;       (* arm_STR X21 SP (Immediate_Offset (word 424)) *)
  0xa95b5bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&432))) *)
  0xeb170063;       (* arm_SUBS X3 X3 X23 *)
  0xfa160084;       (* arm_SBCS X4 X4 X22 *)
  0xa95c5bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&448))) *)
  0xfa1700a5;       (* arm_SBCS X5 X5 X23 *)
  0xfa1600c6;       (* arm_SBCS X6 X6 X22 *)
  0xda9f23f8;       (* arm_CSETM X24 Condition_CC *)
  0xa9495bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&144))) *)
  0xeb0702e7;       (* arm_SUBS X7 X23 X7 *)
  0xfa0802c8;       (* arm_SBCS X8 X22 X8 *)
  0xa94a5bf7;       (* arm_LDP X23 X22 SP (Immediate_Offset (iword (&160))) *)
  0xfa0902e9;       (* arm_SBCS X9 X23 X9 *)
  0xfa0a02ca;       (* arm_SBCS X10 X22 X10 *)
  0xda9f23f9;       (* arm_CSETM X25 Condition_CC *)
  0xca180063;       (* arm_EOR X3 X3 X24 *)
  0xeb180063;       (* arm_SUBS X3 X3 X24 *)
  0xca180084;       (* arm_EOR X4 X4 X24 *)
  0xfa180084;       (* arm_SBCS X4 X4 X24 *)
  0xca1800a5;       (* arm_EOR X5 X5 X24 *)
  0xfa1800a5;       (* arm_SBCS X5 X5 X24 *)
  0xca1800c6;       (* arm_EOR X6 X6 X24 *)
  0xda1800c6;       (* arm_SBC X6 X6 X24 *)
  0xca1900e7;       (* arm_EOR X7 X7 X25 *)
  0xeb1900e7;       (* arm_SUBS X7 X7 X25 *)
  0xca190108;       (* arm_EOR X8 X8 X25 *)
  0xfa190108;       (* arm_SBCS X8 X8 X25 *)
  0xca190129;       (* arm_EOR X9 X9 X25 *)
  0xfa190129;       (* arm_SBCS X9 X9 X25 *)
  0xca19014a;       (* arm_EOR X10 X10 X25 *)
  0xda19014a;       (* arm_SBC X10 X10 X25 *)
  0xca180339;       (* arm_EOR X25 X25 X24 *)
  0x9b077c6b;       (* arm_MUL X11 X3 X7 *)
  0x9b087c8f;       (* arm_MUL X15 X4 X8 *)
  0x9b097cb0;       (* arm_MUL X16 X5 X9 *)
  0x9b0a7cd1;       (* arm_MUL X17 X6 X10 *)
  0x9bc77c73;       (* arm_UMULH X19 X3 X7 *)
  0xab1301ef;       (* arm_ADDS X15 X15 X19 *)
  0x9bc87c93;       (* arm_UMULH X19 X4 X8 *)
  0xba130210;       (* arm_ADCS X16 X16 X19 *)
  0x9bc97cb3;       (* arm_UMULH X19 X5 X9 *)
  0xba130231;       (* arm_ADCS X17 X17 X19 *)
  0x9bca7cd3;       (* arm_UMULH X19 X6 X10 *)
  0x9a1f0273;       (* arm_ADC X19 X19 XZR *)
  0xab0b01ec;       (* arm_ADDS X12 X15 X11 *)
  0xba0f020f;       (* arm_ADCS X15 X16 X15 *)
  0xba100230;       (* arm_ADCS X16 X17 X16 *)
  0xba110271;       (* arm_ADCS X17 X19 X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xab0b01ed;       (* arm_ADDS X13 X15 X11 *)
  0xba0c020e;       (* arm_ADCS X14 X16 X12 *)
  0xba0f022f;       (* arm_ADCS X15 X17 X15 *)
  0xba100270;       (* arm_ADCS X16 X19 X16 *)
  0xba1103f1;       (* arm_ADCS X17 XZR X17 *)
  0x9a1303f3;       (* arm_ADC X19 XZR X19 *)
  0xeb0600b8;       (* arm_SUBS X24 X5 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb090156;       (* arm_SUBS X22 X10 X9 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba170210;       (* arm_ADCS X16 X16 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160231;       (* arm_ADCS X17 X17 X22 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb040078;       (* arm_SUBS X24 X3 X4 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070116;       (* arm_SUBS X22 X8 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba17018c;       (* arm_ADCS X12 X12 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ad;       (* arm_ADCS X13 X13 X22 *)
  0xba1501ce;       (* arm_ADCS X14 X14 X21 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060098;       (* arm_SUBS X24 X4 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080156;       (* arm_SUBS X22 X10 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ef;       (* arm_ADCS X15 X15 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba160210;       (* arm_ADCS X16 X16 X22 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050078;       (* arm_SUBS X24 X3 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070136;       (* arm_SUBS X22 X9 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ad;       (* arm_ADCS X13 X13 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ce;       (* arm_ADCS X14 X14 X22 *)
  0xba1501ef;       (* arm_ADCS X15 X15 X21 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb060078;       (* arm_SUBS X24 X3 X6 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb070156;       (* arm_SUBS X22 X10 X7 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xeb050098;       (* arm_SUBS X24 X4 X5 *)
  0xda982718;       (* arm_CNEG X24 X24 Condition_CC *)
  0xda9f23f5;       (* arm_CSETM X21 Condition_CC *)
  0xeb080136;       (* arm_SUBS X22 X9 X8 *)
  0xda9626d6;       (* arm_CNEG X22 X22 Condition_CC *)
  0x9b167f17;       (* arm_MUL X23 X24 X22 *)
  0x9bd67f16;       (* arm_UMULH X22 X24 X22 *)
  0xda9522b5;       (* arm_CINV X21 X21 Condition_CC *)
  0xb10006bf;       (* arm_CMN X21 (rvalue (word 1)) *)
  0xca1502f7;       (* arm_EOR X23 X23 X21 *)
  0xba1701ce;       (* arm_ADCS X14 X14 X23 *)
  0xca1502d6;       (* arm_EOR X22 X22 X21 *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba150210;       (* arm_ADCS X16 X16 X21 *)
  0xba150231;       (* arm_ADCS X17 X17 X21 *)
  0x9a150273;       (* arm_ADC X19 X19 X21 *)
  0xa95693e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&360))) *)
  0xa9579be5;       (* arm_LDP X5 X6 SP (Immediate_Offset (iword (&376))) *)
  0xca19016b;       (* arm_EOR X11 X11 X25 *)
  0xab03016b;       (* arm_ADDS X11 X11 X3 *)
  0xca19018c;       (* arm_EOR X12 X12 X25 *)
  0xba04018c;       (* arm_ADCS X12 X12 X4 *)
  0xca1901ad;       (* arm_EOR X13 X13 X25 *)
  0xba0501ad;       (* arm_ADCS X13 X13 X5 *)
  0xca1901ce;       (* arm_EOR X14 X14 X25 *)
  0xba0601ce;       (* arm_ADCS X14 X14 X6 *)
  0xca1901ef;       (* arm_EOR X15 X15 X25 *)
  0xa958a3e7;       (* arm_LDP X7 X8 SP (Immediate_Offset (iword (&392))) *)
  0xa959abe9;       (* arm_LDP X9 X10 SP (Immediate_Offset (iword (&408))) *)
  0xf940d7f4;       (* arm_LDR X20 SP (Immediate_Offset (word 424)) *)
  0xba0701ef;       (* arm_ADCS X15 X15 X7 *)
  0xca190210;       (* arm_EOR X16 X16 X25 *)
  0xba080210;       (* arm_ADCS X16 X16 X8 *)
  0xca190231;       (* arm_EOR X17 X17 X25 *)
  0xba090231;       (* arm_ADCS X17 X17 X9 *)
  0xca190273;       (* arm_EOR X19 X19 X25 *)
  0xba0a0273;       (* arm_ADCS X19 X19 X10 *)
  0x9a1f0295;       (* arm_ADC X21 X20 XZR *)
  0xab0301ef;       (* arm_ADDS X15 X15 X3 *)
  0xba040210;       (* arm_ADCS X16 X16 X4 *)
  0xba050231;       (* arm_ADCS X17 X17 X5 *)
  0xba060273;       (* arm_ADCS X19 X19 X6 *)
  0x92402339;       (* arm_AND X25 X25 (rvalue (word 511)) *)
  0xd377d978;       (* arm_LSL X24 X11 9 *)
  0xaa190318;       (* arm_ORR X24 X24 X25 *)
  0xba1800e7;       (* arm_ADCS X7 X7 X24 *)
  0x93cbdd98;       (* arm_EXTR X24 X12 X11 55 *)
  0xba180108;       (* arm_ADCS X8 X8 X24 *)
  0x93ccddb8;       (* arm_EXTR X24 X13 X12 55 *)
  0xba180129;       (* arm_ADCS X9 X9 X24 *)
  0x93cdddd8;       (* arm_EXTR X24 X14 X13 55 *)
  0xba18014a;       (* arm_ADCS X10 X10 X24 *)
  0xd377fdd8;       (* arm_LSR X24 X14 55 *)
  0x9a140314;       (* arm_ADC X20 X24 X20 *)
  0xf9406be6;       (* arm_LDR X6 SP (Immediate_Offset (word 208)) *)
  0xa95b13e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&432))) *)
  0x9240cc77;       (* arm_AND X23 X3 (rvalue (word 4503599627370495)) *)
  0x9b177cd7;       (* arm_MUL X23 X6 X23 *)
  0xf940fbee;       (* arm_LDR X14 SP (Immediate_Offset (word 496)) *)
  0xa94933eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&144))) *)
  0x9240cd78;       (* arm_AND X24 X11 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0x93c3d098;       (* arm_EXTR X24 X4 X3 52 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cbd198;       (* arm_EXTR X24 X12 X11 52 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d732d8;       (* arm_EXTR X24 X22 X23 12 *)
  0xab1801ef;       (* arm_ADDS X15 X15 X24 *)
  0xa95c0fe5;       (* arm_LDP X5 X3 SP (Immediate_Offset (iword (&448))) *)
  0xa94a2fed;       (* arm_LDP X13 X11 SP (Immediate_Offset (iword (&160))) *)
  0x93c4a0b8;       (* arm_EXTR X24 X5 X4 40 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cca1b8;       (* arm_EXTR X24 X13 X12 40 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d662f8;       (* arm_EXTR X24 X23 X22 24 *)
  0xba180210;       (* arm_ADCS X16 X16 X24 *)
  0x93c57078;       (* arm_EXTR X24 X3 X5 28 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cd7178;       (* arm_EXTR X24 X11 X13 28 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d792d8;       (* arm_EXTR X24 X22 X23 36 *)
  0xba180231;       (* arm_ADCS X17 X17 X24 *)
  0x8a110200;       (* arm_AND X0 X16 X17 *)
  0xa95d17e4;       (* arm_LDP X4 X5 SP (Immediate_Offset (iword (&464))) *)
  0xa94b37ec;       (* arm_LDP X12 X13 SP (Immediate_Offset (iword (&176))) *)
  0x93c34098;       (* arm_EXTR X24 X4 X3 16 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cb4198;       (* arm_EXTR X24 X12 X11 16 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd3503eb5;       (* arm_LSL X21 X21 48 *)
  0x8b1502f7;       (* arm_ADD X23 X23 X21 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d6c2f8;       (* arm_EXTR X24 X23 X22 48 *)
  0xba180273;       (* arm_ADCS X19 X19 X24 *)
  0x8a130000;       (* arm_AND X0 X0 X19 *)
  0xd344fc98;       (* arm_LSR X24 X4 4 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0xd344fd98;       (* arm_LSR X24 X12 4 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d7f2d9;       (* arm_EXTR X25 X22 X23 60 *)
  0x93c4e0b8;       (* arm_EXTR X24 X5 X4 56 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cce1b8;       (* arm_EXTR X24 X13 X12 56 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd378df39;       (* arm_LSL X25 X25 8 *)
  0x93d922f8;       (* arm_EXTR X24 X23 X25 8 *)
  0xba1800e7;       (* arm_ADCS X7 X7 X24 *)
  0x8a070000;       (* arm_AND X0 X0 X7 *)
  0xa95e13e3;       (* arm_LDP X3 X4 SP (Immediate_Offset (iword (&480))) *)
  0xa94c33eb;       (* arm_LDP X11 X12 SP (Immediate_Offset (iword (&192))) *)
  0x93c5b078;       (* arm_EXTR X24 X3 X5 44 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0x93cdb178;       (* arm_EXTR X24 X11 X13 44 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d752d8;       (* arm_EXTR X24 X22 X23 20 *)
  0xba180108;       (* arm_ADCS X8 X8 X24 *)
  0x8a080000;       (* arm_AND X0 X0 X8 *)
  0x93c38098;       (* arm_EXTR X24 X4 X3 32 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187cd7;       (* arm_MUL X23 X6 X24 *)
  0x93cb8198;       (* arm_EXTR X24 X12 X11 32 *)
  0x9240cf18;       (* arm_AND X24 X24 (rvalue (word 4503599627370495)) *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374fed8;       (* arm_LSR X24 X22 52 *)
  0x8b1802f7;       (* arm_ADD X23 X23 X24 *)
  0xd374ced6;       (* arm_LSL X22 X22 12 *)
  0x93d682f8;       (* arm_EXTR X24 X23 X22 32 *)
  0xba180129;       (* arm_ADCS X9 X9 X24 *)
  0x8a090000;       (* arm_AND X0 X0 X9 *)
  0xd354fc98;       (* arm_LSR X24 X4 20 *)
  0x9b187cd6;       (* arm_MUL X22 X6 X24 *)
  0xd354fd98;       (* arm_LSR X24 X12 20 *)
  0x9b187dd8;       (* arm_MUL X24 X14 X24 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374fef8;       (* arm_LSR X24 X23 52 *)
  0x8b1802d6;       (* arm_ADD X22 X22 X24 *)
  0xd374cef7;       (* arm_LSL X23 X23 12 *)
  0x93d7b2d8;       (* arm_EXTR X24 X22 X23 44 *)
  0xba18014a;       (* arm_ADCS X10 X10 X24 *)
  0x8a0a0000;       (* arm_AND X0 X0 X10 *)
  0x9b0e7cd8;       (* arm_MUL X24 X6 X14 *)
  0xd36cfed6;       (* arm_LSR X22 X22 44 *)
  0x8b160318;       (* arm_ADD X24 X24 X22 *)
  0x9a180294;       (* arm_ADC X20 X20 X24 *)
  0xd349fe96;       (* arm_LSR X22 X20 9 *)
  0xb277da94;       (* arm_ORR X20 X20 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba1601ff;       (* arm_ADCS XZR X15 X22 *)
  0xba1f001f;       (* arm_ADCS XZR X0 XZR *)
  0xba1f029f;       (* arm_ADCS XZR X20 XZR *)
  0xba1601ef;       (* arm_ADCS X15 X15 X22 *)
  0xba1f0210;       (* arm_ADCS X16 X16 XZR *)
  0xba1f0231;       (* arm_ADCS X17 X17 XZR *)
  0xba1f0273;       (* arm_ADCS X19 X19 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0xba1f014a;       (* arm_ADCS X10 X10 XZR *)
  0x9a1f0294;       (* arm_ADC X20 X20 XZR *)
  0x924021f6;       (* arm_AND X22 X15 (rvalue (word 511)) *)
  0x93cf260f;       (* arm_EXTR X15 X16 X15 9 *)
  0x93d02630;       (* arm_EXTR X16 X17 X16 9 *)
  0xa916c3ef;       (* arm_STP X15 X16 SP (Immediate_Offset (iword (&360))) *)
  0x93d12671;       (* arm_EXTR X17 X19 X17 9 *)
  0x93d324f3;       (* arm_EXTR X19 X7 X19 9 *)
  0xa917cff1;       (* arm_STP X17 X19 SP (Immediate_Offset (iword (&376))) *)
  0x93c72507;       (* arm_EXTR X7 X8 X7 9 *)
  0x93c82528;       (* arm_EXTR X8 X9 X8 9 *)
  0xa918a3e7;       (* arm_STP X7 X8 SP (Immediate_Offset (iword (&392))) *)
  0x93c92549;       (* arm_EXTR X9 X10 X9 9 *)
  0x93ca268a;       (* arm_EXTR X10 X20 X10 9 *)
  0xa919abe9;       (* arm_STP X9 X10 SP (Immediate_Offset (iword (&408))) *)
  0xf900d7f6;       (* arm_STR X22 SP (Immediate_Offset (word 424)) *)
  0xa94d9fe6;       (* arm_LDP X6 X7 SP (Immediate_Offset (iword (&216))) *)
  0xd37ef4c3;       (* arm_LSL X3 X6 2 *)
  0x93c6f8e4;       (* arm_EXTR X4 X7 X6 62 *)
  0xa94ea7e8;       (* arm_LDP X8 X9 SP (Immediate_Offset (iword (&232))) *)
  0x93c7f905;       (* arm_EXTR X5 X8 X7 62 *)
  0x93c8f926;       (* arm_EXTR X6 X9 X8 62 *)
  0xa94fafea;       (* arm_LDP X10 X11 SP (Immediate_Offset (iword (&248))) *)
  0x93c9f947;       (* arm_EXTR X7 X10 X9 62 *)
  0x93caf968;       (* arm_EXTR X8 X11 X10 62 *)
  0xa950b7ec;       (* arm_LDP X12 X13 SP (Immediate_Offset (iword (&264))) *)
  0x93cbf989;       (* arm_EXTR X9 X12 X11 62 *)
  0x93ccf9aa;       (* arm_EXTR X10 X13 X12 62 *)
  0xf9408fee;       (* arm_LDR X14 SP (Immediate_Offset (word 280)) *)
  0x93cdf9cb;       (* arm_EXTR X11 X14 X13 62 *)
  0xa95b07e0;       (* arm_LDP X0 X1 SP (Immediate_Offset (iword (&432))) *)
  0xaa2003e0;       (* arm_MVN X0 X0 *)
  0xab000063;       (* arm_ADDS X3 X3 X0 *)
  0xfa010084;       (* arm_SBCS X4 X4 X1 *)
  0xa95c07e0;       (* arm_LDP X0 X1 SP (Immediate_Offset (iword (&448))) *)
  0xfa0000a5;       (* arm_SBCS X5 X5 X0 *)
  0x8a05008f;       (* arm_AND X15 X4 X5 *)
  0xfa0100c6;       (* arm_SBCS X6 X6 X1 *)
  0x8a0601ef;       (* arm_AND X15 X15 X6 *)
  0xa95d07e0;       (* arm_LDP X0 X1 SP (Immediate_Offset (iword (&464))) *)
  0xfa0000e7;       (* arm_SBCS X7 X7 X0 *)
  0x8a0701ef;       (* arm_AND X15 X15 X7 *)
  0xfa010108;       (* arm_SBCS X8 X8 X1 *)
  0x8a0801ef;       (* arm_AND X15 X15 X8 *)
  0xa95e07e0;       (* arm_LDP X0 X1 SP (Immediate_Offset (iword (&480))) *)
  0xfa000129;       (* arm_SBCS X9 X9 X0 *)
  0x8a0901ef;       (* arm_AND X15 X15 X9 *)
  0xfa01014a;       (* arm_SBCS X10 X10 X1 *)
  0x8a0a01ef;       (* arm_AND X15 X15 X10 *)
  0xf940fbe0;       (* arm_LDR X0 SP (Immediate_Offset (word 496)) *)
  0xd2402000;       (* arm_EOR X0 X0 (rvalue (word 511)) *)
  0x9a00016b;       (* arm_ADC X11 X11 X0 *)
  0xd349fd6c;       (* arm_LSR X12 X11 9 *)
  0xb277d96b;       (* arm_ORR X11 X11 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba0c007f;       (* arm_ADCS XZR X3 X12 *)
  0xba1f01ff;       (* arm_ADCS XZR X15 XZR *)
  0xba1f017f;       (* arm_ADCS XZR X11 XZR *)
  0xba0c0063;       (* arm_ADCS X3 X3 X12 *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0xba1f014a;       (* arm_ADCS X10 X10 XZR *)
  0x9a1f016b;       (* arm_ADC X11 X11 XZR *)
  0x9240216b;       (* arm_AND X11 X11 (rvalue (word 511)) *)
  0xa9001343;       (* arm_STP X3 X4 X26 (Immediate_Offset (iword (&0))) *)
  0xa9011b45;       (* arm_STP X5 X6 X26 (Immediate_Offset (iword (&16))) *)
  0xa9022347;       (* arm_STP X7 X8 X26 (Immediate_Offset (iword (&32))) *)
  0xa9032b49;       (* arm_STP X9 X10 X26 (Immediate_Offset (iword (&48))) *)
  0xf900234b;       (* arm_STR X11 X26 (Immediate_Offset (word 64)) *)
  0xa9569fe6;       (* arm_LDP X6 X7 SP (Immediate_Offset (iword (&360))) *)
  0xd37ff8c3;       (* arm_LSL X3 X6 1 *)
  0xab060063;       (* arm_ADDS X3 X3 X6 *)
  0x93c6fce4;       (* arm_EXTR X4 X7 X6 63 *)
  0xba070084;       (* arm_ADCS X4 X4 X7 *)
  0xa957a7e8;       (* arm_LDP X8 X9 SP (Immediate_Offset (iword (&376))) *)
  0x93c7fd05;       (* arm_EXTR X5 X8 X7 63 *)
  0xba0800a5;       (* arm_ADCS X5 X5 X8 *)
  0x93c8fd26;       (* arm_EXTR X6 X9 X8 63 *)
  0xba0900c6;       (* arm_ADCS X6 X6 X9 *)
  0xa958afea;       (* arm_LDP X10 X11 SP (Immediate_Offset (iword (&392))) *)
  0x93c9fd47;       (* arm_EXTR X7 X10 X9 63 *)
  0xba0a00e7;       (* arm_ADCS X7 X7 X10 *)
  0x93cafd68;       (* arm_EXTR X8 X11 X10 63 *)
  0xba0b0108;       (* arm_ADCS X8 X8 X11 *)
  0xa959b7ec;       (* arm_LDP X12 X13 SP (Immediate_Offset (iword (&408))) *)
  0x93cbfd89;       (* arm_EXTR X9 X12 X11 63 *)
  0xba0c0129;       (* arm_ADCS X9 X9 X12 *)
  0x93ccfdaa;       (* arm_EXTR X10 X13 X12 63 *)
  0xba0d014a;       (* arm_ADCS X10 X10 X13 *)
  0xf940d7ee;       (* arm_LDR X14 SP (Immediate_Offset (word 424)) *)
  0x93cdfdcb;       (* arm_EXTR X11 X14 X13 63 *)
  0x9a0e016b;       (* arm_ADC X11 X11 X14 *)
  0xa95257f4;       (* arm_LDP X20 X21 SP (Immediate_Offset (iword (&288))) *)
  0xaa3403f4;       (* arm_MVN X20 X20 *)
  0xd37df280;       (* arm_LSL X0 X20 3 *)
  0xab000063;       (* arm_ADDS X3 X3 X0 *)
  0xaa3503f5;       (* arm_MVN X21 X21 *)
  0x93d4f6a0;       (* arm_EXTR X0 X21 X20 61 *)
  0xba000084;       (* arm_ADCS X4 X4 X0 *)
  0xa9535ff6;       (* arm_LDP X22 X23 SP (Immediate_Offset (iword (&304))) *)
  0xaa3603f6;       (* arm_MVN X22 X22 *)
  0x93d5f6c0;       (* arm_EXTR X0 X22 X21 61 *)
  0xba0000a5;       (* arm_ADCS X5 X5 X0 *)
  0x8a05008f;       (* arm_AND X15 X4 X5 *)
  0xaa3703f7;       (* arm_MVN X23 X23 *)
  0x93d6f6e0;       (* arm_EXTR X0 X23 X22 61 *)
  0xba0000c6;       (* arm_ADCS X6 X6 X0 *)
  0x8a0601ef;       (* arm_AND X15 X15 X6 *)
  0xa95457f4;       (* arm_LDP X20 X21 SP (Immediate_Offset (iword (&320))) *)
  0xaa3403f4;       (* arm_MVN X20 X20 *)
  0x93d7f680;       (* arm_EXTR X0 X20 X23 61 *)
  0xba0000e7;       (* arm_ADCS X7 X7 X0 *)
  0x8a0701ef;       (* arm_AND X15 X15 X7 *)
  0xaa3503f5;       (* arm_MVN X21 X21 *)
  0x93d4f6a0;       (* arm_EXTR X0 X21 X20 61 *)
  0xba000108;       (* arm_ADCS X8 X8 X0 *)
  0x8a0801ef;       (* arm_AND X15 X15 X8 *)
  0xa9555ff6;       (* arm_LDP X22 X23 SP (Immediate_Offset (iword (&336))) *)
  0xaa3603f6;       (* arm_MVN X22 X22 *)
  0x93d5f6c0;       (* arm_EXTR X0 X22 X21 61 *)
  0xba000129;       (* arm_ADCS X9 X9 X0 *)
  0x8a0901ef;       (* arm_AND X15 X15 X9 *)
  0xaa3703f7;       (* arm_MVN X23 X23 *)
  0x93d6f6e0;       (* arm_EXTR X0 X23 X22 61 *)
  0xba00014a;       (* arm_ADCS X10 X10 X0 *)
  0x8a0a01ef;       (* arm_AND X15 X15 X10 *)
  0xf940b3e0;       (* arm_LDR X0 SP (Immediate_Offset (word 352)) *)
  0xd2402000;       (* arm_EOR X0 X0 (rvalue (word 511)) *)
  0x93d7f400;       (* arm_EXTR X0 X0 X23 61 *)
  0x9a00016b;       (* arm_ADC X11 X11 X0 *)
  0xd349fd6c;       (* arm_LSR X12 X11 9 *)
  0xb277d96b;       (* arm_ORR X11 X11 (rvalue (word 18446744073709551104)) *)
  0xeb1f03ff;       (* arm_CMP XZR XZR *)
  0xba0c007f;       (* arm_ADCS XZR X3 X12 *)
  0xba1f01ff;       (* arm_ADCS XZR X15 XZR *)
  0xba1f017f;       (* arm_ADCS XZR X11 XZR *)
  0xba0c0063;       (* arm_ADCS X3 X3 X12 *)
  0xba1f0084;       (* arm_ADCS X4 X4 XZR *)
  0xba1f00a5;       (* arm_ADCS X5 X5 XZR *)
  0xba1f00c6;       (* arm_ADCS X6 X6 XZR *)
  0xba1f00e7;       (* arm_ADCS X7 X7 XZR *)
  0xba1f0108;       (* arm_ADCS X8 X8 XZR *)
  0xba1f0129;       (* arm_ADCS X9 X9 XZR *)
  0xba1f014a;       (* arm_ADCS X10 X10 XZR *)
  0x9a1f016b;       (* arm_ADC X11 X11 XZR *)
  0x9240216b;       (* arm_AND X11 X11 (rvalue (word 511)) *)
  0xa9049343;       (* arm_STP X3 X4 X26 (Immediate_Offset (iword (&72))) *)
  0xa9059b45;       (* arm_STP X5 X6 X26 (Immediate_Offset (iword (&88))) *)
  0xa906a347;       (* arm_STP X7 X8 X26 (Immediate_Offset (iword (&104))) *)
  0xa907ab49;       (* arm_STP X9 X10 X26 (Immediate_Offset (iword (&120))) *)
  0xf900474b;       (* arm_STR X11 X26 (Immediate_Offset (word 136)) *)
  0x910803ff;       (* arm_ADD SP SP (rvalue (word 512)) *)
  0xa8c173fb;       (* arm_LDP X27 X28 SP (Postimmediate_Offset (iword (&16))) *)
  0xa8c16bf9;       (* arm_LDP X25 X26 SP (Postimmediate_Offset (iword (&16))) *)
  0xa8c163f7;       (* arm_LDP X23 X24 SP (Postimmediate_Offset (iword (&16))) *)
  0xa8c15bf5;       (* arm_LDP X21 X22 SP (Postimmediate_Offset (iword (&16))) *)
  0xa8c153f3;       (* arm_LDP X19 X20 SP (Postimmediate_Offset (iword (&16))) *)
  0xd65f03c0        (* arm_RET X30 *)
];;

let P521_JDOUBLE_EXEC = ARM_MK_EXEC_RULE p521_jdouble_mc;;

(* ------------------------------------------------------------------------- *)
(* Common supporting definitions and lemmas for component proofs.            *)
(* ------------------------------------------------------------------------- *)

let P_521_AS_WORDLIST = prove
 (`p_521 =
   bignum_of_wordlist
    [word_not(word 0);word_not(word 0);word_not(word 0);word_not(word 0);
     word_not(word 0);word_not(word 0);word_not(word 0);word_not(word 0);
     word(0x1FF)]`,
  REWRITE_TAC[p_521; bignum_of_wordlist] THEN
  CONV_TAC WORD_REDUCE_CONV THEN CONV_TAC NUM_REDUCE_CONV);;

let BIGNUM_FROM_MEMORY_EQ_P521 = prove
 (`bignum_of_wordlist[n0;n1;n2;n3;n4;n5;n6;n7;n8] = p_521 <=>
   (!i. i < 64
        ==> bit i n0 /\ bit i n1 /\ bit i n2 /\ bit i n3 /\
            bit i n4 /\ bit i n5 /\ bit i n6 /\ bit i n7) /\
   (!i. i < 9 ==> bit i n8) /\ (!i. i < 64 ==> 9 <= i ==> ~bit i n8)`,
  REWRITE_TAC[P_521_AS_WORDLIST; BIGNUM_OF_WORDLIST_EQ] THEN
  REWRITE_TAC[WORD_EQ_BITS_ALT; DIMINDEX_64] THEN
  CONV_TAC(ONCE_DEPTH_CONV EXPAND_CASES_CONV) THEN
  CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC WORD_REDUCE_CONV THEN
  CONV_TAC CONJ_ACI_RULE);;

let BIGNUM_FROM_MEMORY_LE_P521 = prove
 (`bignum_of_wordlist[n0;n1;n2;n3;n4;n5;n6;n7;n8] <= p_521 <=>
   !i. i < 64 ==> 9 <= i ==> ~bit i n8`,
  SIMP_TAC[P_521; ARITH_RULE `p_521 = 2 EXP 521 - 1 ==>
    (n <= p_521 <=> n DIV 2 EXP (8 * 64) < 2 EXP 9)`] THEN
  REWRITE_TAC[TOP_DEPTH_CONV num_CONV `8`; MULT_CLAUSES; EXP_ADD] THEN
  REWRITE_TAC[GSYM DIV_DIV; BIGNUM_OF_WORDLIST_DIV; EXP; DIV_1] THEN
  REWRITE_TAC[BIGNUM_OF_WORDLIST_SING; GSYM UPPER_BITS_ZERO] THEN
  MP_TAC(ISPEC `n8:int64` BIT_TRIVIAL) THEN REWRITE_TAC[DIMINDEX_64] THEN
  MESON_TAC[NOT_LE]);;

let BIGNUM_FROM_MEMORY_LT_P521 = prove
 (`bignum_of_wordlist[n0;n1;n2;n3;n4;n5;n6;n7;n8] < p_521 <=>
   (!i. i < 64 ==> 9 <= i ==> ~bit i n8) /\
   ~((!i. i < 64
          ==> bit i n0 /\ bit i n1 /\ bit i n2 /\ bit i n3 /\
              bit i n4 /\ bit i n5 /\ bit i n6 /\ bit i n7) /\
     (!i. i < 9 ==> bit i n8))`,
  GEN_REWRITE_TAC LAND_CONV [LT_LE] THEN
  REWRITE_TAC[BIGNUM_FROM_MEMORY_EQ_P521; BIGNUM_FROM_MEMORY_LE_P521] THEN
  MESON_TAC[]);;

let lemma1 = prove
 (`!(x0:num) x1 (y0:num) y1.
       (if y0 <= y1
        then if x1 <= x0 then word 0 else word 18446744073709551615
        else word_not
         (if x1 <= x0 then word 0 else word 18446744073709551615)):int64 =
   word_neg(word(bitval(y0 <= y1 <=> x0 < x1)))`,
  REPEAT GEN_TAC THEN REWRITE_TAC[GSYM NOT_LE] THEN
  REPEAT(COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES]) THEN
  CONV_TAC WORD_REDUCE_CONV);;

let lemma2 = prove
 (`!(x0:int64) (x1:int64) (y0:int64) (y1:int64).
        &(val(if val x1 <= val x0 then word_sub x0 x1
              else word_neg (word_sub x0 x1))) *
        &(val(if val y0 <= val y1 then word_sub y1 y0
              else word_neg (word_sub y1 y0))):real =
        --(&1) pow bitval(val y0 <= val y1 <=> val x0 < val x1) *
        (&(val x0) - &(val x1)) * (&(val y1) - &(val y0))`,
  REPEAT GEN_TAC THEN REWRITE_TAC[GSYM NOT_LE; WORD_NEG_SUB] THEN
  REPEAT(COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES]) THEN
  REPEAT(FIRST_X_ASSUM(ASSUME_TAC o MATCH_MP (ARITH_RULE
   `~(m:num <= n) ==> n <= m /\ ~(m <= n)`))) THEN
  ASM_SIMP_TAC[VAL_WORD_SUB_CASES; GSYM REAL_OF_NUM_SUB] THEN
  REAL_ARITH_TAC);;

let ADK_48_TAC =
  MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
  MAP_EVERY EXISTS_TAC [`512`; `&0:real`] THEN
  REPLICATE_TAC 2 (CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC]) THEN
  CONJ_TAC THENL [REAL_INTEGER_TAC; ALL_TAC] THEN
  ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
  POP_ASSUM_LIST(K ALL_TAC) THEN
  REWRITE_TAC[lemma1; lemma2] THEN REWRITE_TAC[WORD_XOR_MASK] THEN
  REPEAT(COND_CASES_TAC THEN
         ASM_REWRITE_TAC[BITVAL_CLAUSES; REAL_VAL_WORD_NOT]) THEN
  CONV_TAC WORD_REDUCE_CONV THEN CONV_TAC NUM_REDUCE_CONV THEN
  REWRITE_TAC[BITVAL_CLAUSES; DIMINDEX_64] THEN
  POP_ASSUM_LIST(K ALL_TAC) THEN DISCH_TAC THEN
  FIRST_ASSUM(MP_TAC o end_itlist CONJ o DESUM_RULE o CONJUNCTS) THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN
  CONV_TAC(RAND_CONV REAL_POLY_CONV) THEN
  FIRST_ASSUM(MP_TAC o end_itlist CONJ o filter (is_ratconst o rand o concl) o
             DECARRY_RULE o CONJUNCTS) THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;;

let lvs =
 ["x_1",[`X27`;`0`];
  "y_1",[`X27`;`72`];
  "z_1",[`X27`;`144`];
  "x_3",[`X26`;`0`];
  "y_3",[`X26`;`72`];
  "z_3",[`X26`;`144`];
  "z2",[`SP`;`0`];
  "y2",[`SP`;`72`];
  "x2p",[`SP`;`144`];
  "xy2",[`SP`;`216`];
  "y4",[`SP`;`288`];
  "t2",[`SP`;`288`];
  "dx2",[`SP`;`360`];
  "t1",[`SP`;`360`];
  "d",[`SP`;`432`];
  "x4p",[`SP`;`432`]];;

let DESUM_RULE' = cache DESUM_RULE and DECARRY_RULE' = cache DECARRY_RULE;;

(* ------------------------------------------------------------------------- *)
(* Instances of sqr.                                                         *)
(* ------------------------------------------------------------------------- *)

let LOCAL_SQR_P521_TAC =
  ARM_MACRO_SIM_ABBREV_TAC p521_jdouble_mc 412 lvs
  `!(t:armstate) pcin pcout p3 n3 p1 n1.
    !n. read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) t = n
    ==>
    aligned 16 (read SP t) /\
    nonoverlapping (word pc,0x4444) (word_add (read p3 t) (word n3),72)
    ==> ensures arm
         (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
              read PC s = pcin /\
              read SP s = read SP t /\
              read X26 s = read X26 t /\
              read X27 s = read X27 t /\
              read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) s =
              n)
         (\s. read PC s = pcout /\
              (n < p_521
               ==> read(memory :> bytes(word_add (read p3 t) (word n3),
                        8 * 9)) s = (n EXP 2) MOD p_521))
         (MAYCHANGE [PC; X0; X1; X2; X3; X4; X5; X6; X7; X8; X9; X10;
                     X11; X12; X13; X14; X15; X16; X17; X19; X20;
                     X21; X22; X23; X24; X25] ,,
          MAYCHANGE
           [memory :> bytes(word_add (read p3 t) (word n3),8 * 9)] ,,
          MAYCHANGE SOME_FLAGS)`
 (REWRITE_TAC[C_ARGUMENTS; C_RETURN; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN ASSUME_TAC) THEN

  (*** Globalize the n < p_521 assumption for simplicity's sake ***)

  ASM_CASES_TAC `n < p_521` THENL
   [ASM_REWRITE_TAC[]; ARM_SIM_TAC P521_JDOUBLE_EXEC (1--412)] THEN

  (*** Digitize, deduce the bound on the top word specifically ***)

  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "n_" o lhand o concl) THEN
  SUBGOAL_THEN `n DIV 2 EXP 512 < 2 EXP 9` MP_TAC THENL
   [UNDISCH_TAC `n < p_521` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
    FIRST_ASSUM(fun th -> GEN_REWRITE_TAC (funpow 3 LAND_CONV) [SYM th]) THEN
    CONV_TAC(LAND_CONV(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV)) THEN
    DISCH_TAC] THEN

  (*** The 4x4 squaring of the top "half" ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [5; 6; 13; 18; 19; 21; 22; 23; 24; 25; 27; 28; 29; 30; 31;
    32; 33; 34; 35; 36; 37; 41; 42; 43; 44; 45; 46; 47; 48; 49;
    50; 51; 52; 53; 54; 58; 59; 60; 61; 62; 63; 64; 65; 66; 67]
   (1--67) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist[n_4; n_5; n_6; n_7] EXP 2 =
    bignum_of_wordlist
      [mullo_s35; sum_s44; sum_s47; sum_s48; sum_s64; sum_s65; sum_s66;
       sum_s67]`
  ASSUME_TAC THENL
   [REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`512`; `&0:real`] THEN
    REPLICATE_TAC 2 (CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC]) THEN
    CONJ_TAC THENL [REAL_INTEGER_TAC; ALL_TAC] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
    POP_ASSUM_LIST(K ALL_TAC) THEN
    REWRITE_TAC[lemma1; lemma2] THEN REWRITE_TAC[WORD_XOR_MASK] THEN
    COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES; REAL_VAL_WORD_NOT] THEN
    CONV_TAC WORD_REDUCE_CONV THEN CONV_TAC NUM_REDUCE_CONV THEN
    REWRITE_TAC[BITVAL_CLAUSES; DIMINDEX_64; ADD_CLAUSES; VAL_WORD_BITVAL] THEN
    POP_ASSUM_LIST(K ALL_TAC) THEN DISCH_TAC THEN
    FIRST_ASSUM(MP_TAC o end_itlist CONJ o DESUM_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN
    CONV_TAC(RAND_CONV REAL_POLY_CONV) THEN FIRST_ASSUM
     (MP_TAC o end_itlist CONJ o filter (is_ratconst o rand o concl) o
      DECARRY_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** The complicated augmentation with the little word contribution ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [70; 80; 88; 96; 104; 119; 127; 135; 142; 144]
   (68--144) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist[n_4; n_5; n_6; n_7; n_8] EXP 2 +
    2 * val n_8 * bignum_of_wordlist[n_0; n_1; n_2; n_3] =
    bignum_of_wordlist[sum_s80; sum_s88; sum_s96; sum_s104;
                       sum_s119; sum_s127; sum_s135; sum_s142; sum_s144]`
  ASSUME_TAC THENL
   [REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(4,1)] THEN
    ASM_REWRITE_TAC[BIGNUM_OF_WORDLIST_SING; ARITH_RULE
     `(l + 2 EXP 256 * h) EXP 2 =
      2 EXP 512 * h EXP 2 + 2 EXP 256 * (2 * h) * l + l EXP 2`] THEN
    REWRITE_TAC[ARITH_RULE
     `(x + 2 EXP 256 * (2 * c) * h + y) + 2 * c * l =
      x + y + 2 * c * (l + 2 EXP 256 * h)`] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_EQ] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN
    CONJ_TAC THENL
     [REWRITE_TAC[REAL_OF_NUM_CLAUSES; LE_0] THEN
      MATCH_MP_TAC(ARITH_RULE
       `c2 < 2 EXP 9 EXP 2 /\ x < 2 EXP 512 /\ c * y <= 2 EXP 9 * 2 EXP 512
        ==> 2 EXP 512 * c2 + x + 2 * c * y < 2 EXP 576`) THEN
      ASM_REWRITE_TAC[EXP_MONO_LT; ARITH_EQ] THEN CONJ_TAC THENL
       [ALL_TAC; MATCH_MP_TAC LE_MULT2 THEN ASM_SIMP_TAC[LT_IMP_LE]] THEN
      REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
      BOUNDER_TAC[];
      ALL_TAC] THEN
    CONJ_TAC THENL
     [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
      BOUNDER_TAC[];
      REWRITE_TAC[INTEGER_CLOSED]] THEN
    ASM_REWRITE_TAC[ARITH_RULE
     `(x + 2 EXP 256 * (2 * c) * h + y) + 2 * c * l =
      x + y + 2 * c * (l + 2 EXP 256 * h)`] THEN
    REWRITE_TAC[GSYM(BIGNUM_OF_WORDLIST_SPLIT_RULE(4,4))] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
    REWRITE_TAC[DIMINDEX_64; ADD_CLAUSES] THEN
    CONV_TAC(ONCE_DEPTH_CONV NUM_MOD_CONV) THEN
    SUBST1_TAC(SYM(NUM_REDUCE_CONV `2 EXP 52 - 1`)) THEN
    REWRITE_TAC[WORD_RULE
     `word(val(word_add (x:int64) x) * val(y:int64)):int64 =
      word(2 * val x * val y)`] THEN
    MAP_EVERY ABBREV_TAC
     [`d0:int64 = word_and n_0 (word (2 EXP 52 - 1))`;
      `d1:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) n_1 n_0) (52,64))
                           (word (2 EXP 52 - 1))`;
      `d2:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) n_2 n_1) (40,64))
                           (word (2 EXP 52 - 1))`;
      `d3:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) n_3 n_2) (28,64))
                           (word (2 EXP 52 - 1))`;
      `d4:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) n_4 n_3) (16,64))
                           (word (2 EXP 52 - 1))`;
      `d5:int64 = word_and (word_ushr n_4 4) (word (2 EXP 52 - 1))`;
      `d6:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) n_5 n_4) (56,64))
                           (word (2 EXP 52 - 1))`;
      `d7:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) n_6 n_5) (44,64))
                           (word (2 EXP 52 - 1))`;
      `d8:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) n_7 n_6) (32,64))
                           (word (2 EXP 52 - 1))`;
      `d9:int64 = word_ushr n_7 20`;
      `e0:int64 = word(2 * val(n_8:int64) * val(d0:int64))`;
      `e1:int64 =
       word_add(word(2 * val(n_8:int64) * val(d1:int64))) (word_ushr e0 52)`;
      `e2:int64 =
       word_add(word(2 * val(n_8:int64) * val(d2:int64))) (word_ushr e1 52)`;
      `e3:int64 =
       word_add(word(2 * val(n_8:int64) * val(d3:int64))) (word_ushr e2 52)`;
      `e4:int64 =
       word_add(word(2 * val(n_8:int64) * val(d4:int64))) (word_ushr e3 52)`;
      `e5:int64 =
       word_add(word(2 * val(n_8:int64) * val(d5:int64))) (word_ushr e4 52)`;
      `e6:int64 =
       word_add(word(2 * val(n_8:int64) * val(d6:int64))) (word_ushr e5 52)`;
      `e7:int64 =
       word_add(word(2 * val(n_8:int64) * val(d7:int64))) (word_ushr e6 52)`;
      `e8:int64 =
       word_add(word(2 * val(n_8:int64) * val(d8:int64))) (word_ushr e7 52)`;
      `e9:int64 =
       word_add(word(2 * val(n_8:int64) * val(d9:int64))) (word_ushr e8 52)`;
      `f0:int64 = word_subword
       ((word_join:int64->int64->int128) e1 (word_shl e0 12)) (12,64)`;
      `f1:int64 = word_subword
       ((word_join:int64->int64->int128) e2 (word_shl e1 12)) (24,64)`;
      `f2:int64 = word_subword
       ((word_join:int64->int64->int128) e3 (word_shl e2 12)) (36,64)`;
      `f3:int64 = word_subword
       ((word_join:int64->int64->int128) e4 (word_shl e3 12)) (48,64)`;
      `f4:int64 = word_subword
        ((word_join:int64->int64->int128) e6
        (word_shl (word_subword ((word_join:int64->int64->int128) e5
              (word_shl e4 12)) (60,64)) 8)) (8,64)`;
      `f5:int64 = word_subword
       ((word_join:int64->int64->int128) e7 (word_shl e6 12)) (20,64)`;
      `f6:int64 = word_subword
        ((word_join:int64->int64->int128) e8 (word_shl e7 12)) (32,64)`;
      `f7:int64 = word_subword
        ((word_join:int64->int64->int128) e9 (word_shl e8 12)) (44,64)`;
      `f8:int64 = word_ushr e9 44`] THEN
    SUBGOAL_THEN
     `2 * val(n_8:int64) *
      bignum_of_wordlist[n_0; n_1; n_2; n_3; n_4; n_5; n_6; n_7] =
      bignum_of_wordlist[f0;f1;f2;f3;f4;f5;f6;f7;f8]`
    SUBST1_TAC THENL
     [SUBGOAL_THEN
       `bignum_of_wordlist[n_0; n_1; n_2; n_3; n_4; n_5; n_6; n_7] =
        ITLIST (\(h:int64) t. val h + 2 EXP 52 * t)
               [d0;d1;d2;d3;d4;d5;d6;d7;d8;d9] 0 /\
        bignum_of_wordlist[f0; f1; f2; f3; f4; f5; f6; f7; f8] =
        2 EXP 520 * val(e9:int64) DIV 2 EXP 52 +
        ITLIST (\(h:int64) t. val h MOD 2 EXP 52 + 2 EXP 52 * t)
               [e0; e1; e2; e3; e4; e5; e6; e7; e8; e9] 0`
      (CONJUNCTS_THEN SUBST1_TAC) THENL
       [REWRITE_TAC[ITLIST; ADD_CLAUSES; MULT_CLAUSES; bignum_of_wordlist] THEN
        REWRITE_TAC[GSYM VAL_WORD_USHR; GSYM VAL_WORD_AND_MASK_WORD] THEN
        CONJ_TAC THENL
         [MAP_EVERY EXPAND_TAC
           ["d0"; "d1"; "d2"; "d3"; "d4"; "d5"; "d6"; "d7"; "d8"; "d9"];
          MAP_EVERY EXPAND_TAC
           ["f0"; "f1"; "f2"; "f3"; "f4"; "f5"; "f6"; "f7"; "f8"]] THEN
        CONV_TAC NUM_REDUCE_CONV THEN
        REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
        REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
        REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
        REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR;
                    BIT_WORD_AND; BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
        CONV_TAC NUM_REDUCE_CONV THEN
        CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
        CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
        CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
        ONCE_REWRITE_TAC[BIT_GUARD] THEN REWRITE_TAC[DIMINDEX_64] THEN
        CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
        CONV_TAC NUM_RING;
        ALL_TAC] THEN
      SUBGOAL_THEN
       `2 * val(n_8:int64) * val(d0:int64) = val (e0:int64) /\
        2 * val n_8 * val(d1:int64) + val e0 DIV 2 EXP 52 = val(e1:int64) /\
        2 * val n_8 * val(d2:int64) + val e1 DIV 2 EXP 52 = val(e2:int64) /\
        2 * val n_8 * val(d3:int64) + val e2 DIV 2 EXP 52 = val(e3:int64) /\
        2 * val n_8 * val(d4:int64) + val e3 DIV 2 EXP 52 = val(e4:int64) /\
        2 * val n_8 * val(d5:int64) + val e4 DIV 2 EXP 52 = val(e5:int64) /\
        2 * val n_8 * val(d6:int64) + val e5 DIV 2 EXP 52 = val(e6:int64) /\
        2 * val n_8 * val(d7:int64) + val e6 DIV 2 EXP 52 = val(e7:int64) /\
        2 * val n_8 * val(d8:int64) + val e7 DIV 2 EXP 52 = val(e8:int64) /\
        2 * val n_8 * val(d9:int64) + val e8 DIV 2 EXP 52 = val(e9:int64)`
      MP_TAC THENL [ALL_TAC; REWRITE_TAC[ITLIST] THEN ARITH_TAC] THEN
      REPEAT CONJ_TAC THEN FIRST_X_ASSUM(fun th ->
        GEN_REWRITE_TAC (RAND_CONV o RAND_CONV) [SYM th]) THEN
      REWRITE_TAC[VAL_WORD_ADD; VAL_WORD; VAL_WORD_USHR; DIMINDEX_64] THEN
      CONV_TAC SYM_CONV THEN CONV_TAC MOD_DOWN_CONV THEN
      MATCH_MP_TAC MOD_LT THEN
      (MATCH_MP_TAC(ARITH_RULE
        `n * d <= 2 EXP 9 * 2 EXP 52 /\ e < 2 EXP 64
         ==> 2 * n * d + e DIV 2 EXP 52 < 2 EXP 64`) ORELSE
       MATCH_MP_TAC(ARITH_RULE
        `n * d <= 2 EXP 9 * 2 EXP 52 ==> 2 * n * d < 2 EXP 64`)) THEN
      REWRITE_TAC[VAL_BOUND_64] THEN MATCH_MP_TAC LE_MULT2 THEN
      CONJ_TAC THEN MATCH_MP_TAC LT_IMP_LE THEN ASM_REWRITE_TAC[] THEN
      MAP_EVERY EXPAND_TAC
       ["d0"; "d1"; "d2"; "d3"; "d4"; "d5"; "d6"; "d7"; "d8"; "d9"] THEN
      REWRITE_TAC[VAL_WORD_AND_MASK_WORD] THEN TRY ARITH_TAC THEN
      REWRITE_TAC[VAL_WORD_USHR] THEN MATCH_MP_TAC
       (ARITH_RULE `n < 2 EXP 64 ==> n DIV 2 EXP 20 < 2 EXP 52`) THEN
      MATCH_ACCEPT_TAC VAL_BOUND_64;
      ALL_TAC] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    DISCH_THEN(MP_TAC o end_itlist CONJ o DESUM_RULE' o rev o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Rotation of the high portion ***)

  ARM_STEPS_TAC P521_JDOUBLE_EXEC (145--160) THEN
  ABBREV_TAC
   `htop:int64 =
    word_add (word_and sum_s80 (word 511)) (word_ushr sum_s144 9)` THEN
  SUBGOAL_THEN `val(htop:int64) < 2 EXP 56` ASSUME_TAC THENL
   [EXPAND_TAC "htop" THEN REWRITE_TAC[VAL_WORD_ADD] THEN
    W(MP_TAC o PART_MATCH lhand MOD_LE o lhand o snd) THEN
    MATCH_MP_TAC(REWRITE_RULE[IMP_CONJ_ALT] LET_TRANS) THEN
    REWRITE_TAC[DIMINDEX_64; SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
    REWRITE_TAC[VAL_WORD_USHR; VAL_WORD_AND_MASK_WORD] THEN
    MP_TAC(ISPEC `sum_s144:int64` VAL_BOUND_64) THEN ARITH_TAC;
    ALL_TAC] THEN
  ABBREV_TAC
   `h = bignum_of_wordlist
    [word_subword ((word_join:int64->int64->int128) sum_s88 sum_s80) (9,64);
     word_subword ((word_join:int64->int64->int128) sum_s96 sum_s88) (9,64);
     word_subword ((word_join:int64->int64->int128) sum_s104 sum_s96) (9,64);
     word_subword ((word_join:int64->int64->int128) sum_s119 sum_s104) (9,64);
     word_subword ((word_join:int64->int64->int128) sum_s127 sum_s119) (9,64);
     word_subword ((word_join:int64->int64->int128) sum_s135 sum_s127) (9,64);
     word_subword ((word_join:int64->int64->int128) sum_s142 sum_s135) (9,64);
     word_subword ((word_join:int64->int64->int128) sum_s144 sum_s142) (9,64);
     htop]` THEN
  SUBGOAL_THEN
   `n EXP 2 MOD p_521 =
    (2 EXP 257 * bignum_of_wordlist[n_0;n_1;n_2;n_3] *
                 bignum_of_wordlist[n_4;n_5;n_6;n_7] +
     bignum_of_wordlist[n_0;n_1;n_2;n_3] EXP 2 + h) MOD p_521`
  SUBST1_TAC THENL
   [EXPAND_TAC "n" THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(4,5)] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(4,1)] THEN
    REWRITE_TAC[ARITH_RULE
     `(l + 2 EXP 256 * (h + 2 EXP 256 * c)) EXP 2 =
      2 EXP 257 * l * h + l EXP 2 +
      2 EXP 512 * ((h + 2 EXP 256 * c) EXP 2 + 2 * c * l)`] THEN
    REWRITE_TAC[GSYM(BIGNUM_OF_WORDLIST_SPLIT_RULE(4,1))] THEN
    REWRITE_TAC[GSYM CONG; CONG_ADD_LCANCEL_EQ] THEN
    ASM_REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN
    EXPAND_TAC "h" THEN REWRITE_TAC[bignum_of_wordlist] THEN
    SUBGOAL_THEN
    `val(htop:int64) =
     val(word_and sum_s80 (word 511):int64) + val(word_ushr sum_s144 9:int64)`
    SUBST1_TAC THENL
     [EXPAND_TAC "htop" THEN
      REWRITE_TAC[VAL_WORD_ADD; DIMINDEX_64] THEN MATCH_MP_TAC MOD_LT THEN
      REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
      REWRITE_TAC[VAL_WORD_USHR; VAL_WORD_AND_MASK_WORD] THEN
      MP_TAC(ISPEC `sum_s144:int64` VAL_BOUND_64) THEN ARITH_TAC;
      ALL_TAC] THEN
    REWRITE_TAC[REAL_CONGRUENCE; p_521; ARITH_EQ] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
    REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
    REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
    REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR;
                BIT_WORD_AND; BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    ONCE_REWRITE_TAC[BIT_GUARD] THEN REWRITE_TAC[DIMINDEX_64] THEN
    CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; p_521] THEN
    REAL_INTEGER_TAC;
    ALL_TAC] THEN

  (*** Squaring of the lower "half" ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [161; 162; 169; 174; 175; 177; 178; 179; 180; 181; 183; 184; 185; 186; 187;
    188; 189; 190; 191; 192; 193; 197; 198; 199; 200; 201; 202; 203; 204; 205;
    206; 207; 208; 209; 210; 214; 215; 216; 217; 218; 219; 220; 221; 222; 223]
   (161--223) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist[n_0; n_1; n_2; n_3] EXP 2 =
    bignum_of_wordlist
     [mullo_s191; sum_s200; sum_s203; sum_s204;
      sum_s220; sum_s221; sum_s222; sum_s223]`
  SUBST1_TAC THENL
   [REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`512`; `&0:real`] THEN
    REPLICATE_TAC 2 (CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC]) THEN
    CONJ_TAC THENL [REAL_INTEGER_TAC; ALL_TAC] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
    POP_ASSUM_LIST(K ALL_TAC) THEN
    REWRITE_TAC[lemma1; lemma2] THEN REWRITE_TAC[WORD_XOR_MASK] THEN
    COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES; REAL_VAL_WORD_NOT] THEN
    CONV_TAC WORD_REDUCE_CONV THEN CONV_TAC NUM_REDUCE_CONV THEN
    REWRITE_TAC[BITVAL_CLAUSES; DIMINDEX_64; ADD_CLAUSES; VAL_WORD_BITVAL] THEN
    POP_ASSUM_LIST(K ALL_TAC) THEN DISCH_TAC THEN
    FIRST_ASSUM(MP_TAC o end_itlist CONJ o DESUM_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN
    CONV_TAC(RAND_CONV REAL_POLY_CONV) THEN FIRST_ASSUM
     (MP_TAC o end_itlist CONJ o filter (is_ratconst o rand o concl) o
      DECARRY_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Addition of low and rotated high parts ***)

  SUBGOAL_THEN `h < 2 EXP 568` ASSUME_TAC THENL
   [EXPAND_TAC "h" THEN REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    MATCH_MP_TAC(ARITH_RULE
     `l < 2 EXP (64 * 8) /\ h < 2 EXP 56
      ==> l + 2 EXP 512 * h < 2 EXP 568`) THEN
    ASM_REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN
    MATCH_MP_TAC BIGNUM_OF_WORDLIST_BOUND THEN
    REWRITE_TAC[LENGTH] THEN ARITH_TAC;
    ALL_TAC] THEN

  ABBREV_TAC
   `hl = bignum_of_wordlist
         [mullo_s191; sum_s200; sum_s203; sum_s204; sum_s220; sum_s221;
          sum_s222; sum_s223] + h` THEN
  SUBGOAL_THEN `hl < 2 EXP 569` ASSUME_TAC THENL
   [EXPAND_TAC "hl" THEN MATCH_MP_TAC(ARITH_RULE
     `l < 2 EXP (64 * 8) /\ h < 2 EXP 568 ==> l + h < 2 EXP 569`) THEN
    ASM_REWRITE_TAC[] THEN MATCH_MP_TAC BIGNUM_OF_WORDLIST_BOUND THEN
    REWRITE_TAC[LENGTH] THEN ARITH_TAC;
    ALL_TAC] THEN

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [225; 226; 229; 230; 233; 234; 237; 238; 241] (224--242) THEN

  SUBGOAL_THEN
   `bignum_of_wordlist
     [sum_s225;sum_s226;sum_s229;sum_s230;
      sum_s233;sum_s234;sum_s237;sum_s238;sum_s241] = hl`
  MP_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN CONJ_TAC THENL
     [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
      BOUNDER_TAC[];
      ALL_TAC] THEN
    ASM_REWRITE_TAC[REAL_OF_NUM_CLAUSES; INTEGER_CLOSED; LE_0] THEN
    ASM_SIMP_TAC[ARITH_RULE `hl < 2 EXP 569 ==> hl < 2 EXP 576`] THEN
    MAP_EVERY EXPAND_TAC ["hl"; "h"] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN
    FIRST_X_ASSUM(K ALL_TAC o check ((=) `hl:num` o rand o concl)) THEN
    DISCH_TAC] THEN

  (*** The cross-multiplication ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [243; 244; 245; 246; 248; 250; 252; 254; 255; 256; 257; 258;
    259; 260; 261; 262; 263; 264; 265; 271; 276; 278; 279; 285;
    290; 292; 293; 294; 295; 296; 297; 303; 308; 310; 311; 312;
    318; 323; 325; 326; 327; 328; 329; 335; 340; 342; 343; 344;
    345; 351; 356; 358; 359; 360; 361]
   (243--361) THEN

  SUBGOAL_THEN
   `bignum_of_wordlist[n_0;n_1;n_2;n_3] *
    bignum_of_wordlist[n_4;n_5;n_6;n_7] =
    bignum_of_wordlist
     [mullo_s243; sum_s290; sum_s323; sum_s356;
      sum_s358; sum_s359; sum_s360; sum_s361]`
  SUBST1_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`512`; `&0:real`] THEN
    REPLICATE_TAC 2 (CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC]) THEN
    CONJ_TAC THENL [REAL_INTEGER_TAC; ALL_TAC] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
    POP_ASSUM_LIST(K ALL_TAC) THEN
    REWRITE_TAC[lemma1; lemma2] THEN REWRITE_TAC[WORD_XOR_MASK] THEN
    REPEAT(COND_CASES_TAC THEN
           ASM_REWRITE_TAC[BITVAL_CLAUSES; REAL_VAL_WORD_NOT]) THEN
    CONV_TAC WORD_REDUCE_CONV THEN CONV_TAC NUM_REDUCE_CONV THEN
    REWRITE_TAC[BITVAL_CLAUSES; DIMINDEX_64] THEN
    POP_ASSUM_LIST(K ALL_TAC) THEN DISCH_TAC THEN
    FIRST_ASSUM(MP_TAC o end_itlist CONJ o DESUM_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN
    CONV_TAC(RAND_CONV REAL_POLY_CONV) THEN FIRST_ASSUM
     (MP_TAC o end_itlist CONJ o filter (is_ratconst o rand o concl) o
      DECARRY_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Addition of the rotated cross-product to the running total ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [364; 366; 369; 372; 376; 379; 383; 386; 391] (362--391) THEN
  MAP_EVERY ABBREV_TAC
  [`m0:int64 = word_subword
    ((word_join:int64->int64->int128) sum_s359 sum_s358) (8,64)`;
  `m1:int64 = word_subword
    ((word_join:int64->int64->int128) sum_s360 sum_s359) (8,64)`;
  `m2:int64 = word_subword
    ((word_join:int64->int64->int128) sum_s361 sum_s360) (8,64)`;
  `m3:int64 = word_ushr sum_s361 8`;
  `m4:int64 = word_shl mullo_s243 1`;
  `m5:int64 = word_subword
    ((word_join:int64->int64->int128) sum_s290 mullo_s243) (63,64)`;
  `m6:int64 = word_subword
    ((word_join:int64->int64->int128) sum_s323 sum_s290) (63,64)`;
  `m7:int64 = word_subword
    ((word_join:int64->int64->int128) sum_s356 sum_s323) (63,64)`;
  `m8:int64 = word_and
     (word_subword ((word_join:int64->int64->int128) sum_s358 sum_s356)
     (63,64)) (word 511)`] THEN

  SUBGOAL_THEN
   `(2 EXP 257 * bignum_of_wordlist
         [mullo_s243; sum_s290; sum_s323; sum_s356;
          sum_s358; sum_s359; sum_s360; sum_s361] + hl) MOD p_521 =
    (bignum_of_wordlist[m0;m1;m2;m3;m4;m5;m6;m7;m8] + hl) MOD p_521`
  SUBST1_TAC THENL
   [REWRITE_TAC[GSYM CONG; CONG_ADD_RCANCEL_EQ] THEN
    MAP_EVERY EXPAND_TAC
     ["m0"; "m1"; "m2"; "m3"; "m4"; "m5"; "m6"; "m7"; "m8"] THEN
    REWRITE_TAC[REAL_CONGRUENCE; p_521; ARITH_EQ] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
    REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
    REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
    REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR;
                BIT_WORD_AND; BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    ONCE_REWRITE_TAC[BIT_GUARD] THEN REWRITE_TAC[DIMINDEX_64] THEN
    CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; p_521] THEN
    REAL_INTEGER_TAC;
    ALL_TAC] THEN

  ABBREV_TAC
   `m = bignum_of_wordlist
         [sum_s364; sum_s366; sum_s369; sum_s372; sum_s376;
          sum_s379; sum_s383; sum_s386; sum_s391]` THEN
  SUBGOAL_THEN `m < 2 EXP 576` ASSUME_TAC THENL
   [EXPAND_TAC "m" THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    BOUNDER_TAC[];
    ALL_TAC] THEN
  SUBGOAL_THEN
   `bignum_of_wordlist [m0; m1; m2; m3; m4; m5; m6; m7; m8] + hl = m`
  SUBST1_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN CONJ_TAC THENL
     [REWRITE_TAC[REAL_OF_NUM_CLAUSES; LE_0] THEN
      REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
      MATCH_MP_TAC(ARITH_RULE
       `l < 2 EXP (64 * 8) /\ hl < 2 EXP 569 /\ h < 2 EXP 56
        ==> (l + 2 EXP 512 * h) + hl < 2 EXP 576`) THEN
      ASM_REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN CONJ_TAC THENL
       [MATCH_MP_TAC BIGNUM_OF_WORDLIST_BOUND THEN
        REWRITE_TAC[LENGTH] THEN ARITH_TAC;
        EXPAND_TAC "m8" THEN
        REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
        REWRITE_TAC[VAL_WORD_AND_MASK_WORD] THEN ARITH_TAC];
      ALL_TAC] THEN
    ASM_REWRITE_TAC[INTEGER_CLOSED; LE_0; REAL_OF_NUM_CLAUSES] THEN
    MAP_EVERY EXPAND_TAC ["hl"; "m"] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Breaking the problem down to (h + l) MOD p_521 ***)

  SUBGOAL_THEN `m MOD p_521 = (m DIV 2 EXP 521 + m MOD 2 EXP 521) MOD p_521`
  SUBST1_TAC THENL
   [GEN_REWRITE_TAC (LAND_CONV o LAND_CONV)
     [ARITH_RULE `m = 2 EXP 521 * m DIV 2 EXP 521 + m MOD 2 EXP 521`] THEN
    REWRITE_TAC[GSYM CONG] THEN MATCH_MP_TAC(NUMBER_RULE
     `(e == 1) (mod p) ==> (e * h + l == h + l) (mod p)`) THEN
    REWRITE_TAC[p_521; CONG] THEN ARITH_TAC;
    ALL_TAC] THEN
  SUBGOAL_THEN `m DIV 2 EXP 521 < 2 EXP 64 /\ m MOD 2 EXP 521 < 2 EXP 521`
  STRIP_ASSUME_TAC THENL
   [REWRITE_TAC[MOD_LT_EQ] THEN UNDISCH_TAC `m < 2 EXP 576` THEN ARITH_TAC;
    ALL_TAC] THEN

  (*** Splitting up and stuffing 1 bits into the low part ***)

  ARM_STEPS_TAC P521_JDOUBLE_EXEC (392--394) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[GSYM WORD_AND_ASSOC; DIMINDEX_64;
      NUM_REDUCE_CONV `9 MOD 64`]) THEN
  REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `h:num` o concl))) THEN
  MAP_EVERY ABBREV_TAC
   [`h:int64 = word_ushr sum_s391 9`;
    `d:int64 = word_or sum_s391 (word 18446744073709551104)`;
    `dd:int64 = word_and sum_s366 (word_and sum_s369 (word_and sum_s372
      (word_and sum_s376 (word_and sum_s379
         (word_and sum_s383 sum_s386)))))`] THEN

  (*** The comparison in its direct condensed form ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (395--397) (395--397) THEN
  SUBGOAL_THEN
   `carry_s397 <=>
    2 EXP 192 <=
      2 EXP 128 * val(d:int64) + 2 EXP 64 * val(dd:int64) +
      val(h:int64) + val(sum_s364:int64) + 1`
  (ASSUME_TAC o SYM) THENL
   [MATCH_MP_TAC FLAG_FROM_CARRY_LE THEN EXISTS_TAC `192` THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DECARRY_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN BOUNDER_TAC[];
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Finish the simulation before completing the mathematics ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (398--406) (398--412) THEN
  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN
  CONV_TAC(LAND_CONV BIGNUM_LEXPAND_CONV) THEN ASM_REWRITE_TAC[] THEN
  DISCARD_STATE_TAC "s412" THEN

  (*** Evaluate d and un-condense the inequality ***)

  SUBGOAL_THEN
   `val(d:int64) = 2 EXP 9 * (2 EXP 55 - 1) + val(sum_s391:int64) MOD 2 EXP 9`
  SUBST_ALL_TAC THENL
   [EXPAND_TAC "d" THEN ONCE_REWRITE_TAC[WORD_BITWISE_RULE
     `word_or a b = word_or b (word_and a (word_not b))`] THEN
    SIMP_TAC[VAL_WORD_OR_DISJOINT; WORD_BITWISE_RULE
     `word_and x (word_and y (word_not x)) = word 0`] THEN
    REWRITE_TAC[GSYM VAL_WORD_AND_MASK_WORD] THEN
    CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC WORD_REDUCE_CONV;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 512 * val(sum_s391:int64) MOD 2 EXP 9 +
    bignum_of_wordlist
     [sum_s364; sum_s366; sum_s369; sum_s372; sum_s376;
      sum_s379; sum_s383; sum_s386] =
    m MOD 2 EXP 521`
  (LABEL_TAC "*") THENL
   [CONV_TAC SYM_CONV THEN EXPAND_TAC "m" THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    REWRITE_TAC[ARITH_RULE `2 EXP 521 = 2 EXP 512 * 2 EXP 9`] THEN
    REWRITE_TAC[SYM(NUM_REDUCE_CONV `64 * 8`)] THEN
    SIMP_TAC[LENGTH; ARITH_LT; ARITH_LE; MOD_MULT_MOD; ADD_CLAUSES;
             ARITH_SUC; BIGNUM_OF_WORDLIST_BOUND; MOD_LT; DIV_LT;
             MOD_MULT_ADD; DIV_MULT_ADD; EXP_EQ_0; ARITH_EQ] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN ARITH_TAC;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 521 <= m MOD 2 EXP 521 + val(h:int64) + 1 <=> carry_s397`
  MP_TAC THENL
   [REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN EXPAND_TAC "carry_s397" THEN
    ONCE_REWRITE_TAC[bignum_of_wordlist] THEN
    MATCH_MP_TAC(TAUT
     `!p q. ((p ==> ~r) /\ (q ==> ~s)) /\ (p <=> q) /\ (~p /\ ~q ==> (r <=> s))
            ==> (r <=> s)`) THEN
    MAP_EVERY EXISTS_TAC
     [`bignum_of_wordlist
        [sum_s366; sum_s369; sum_s372; sum_s376; sum_s379; sum_s383; sum_s386] <
       2 EXP (64 * 7) - 1`;
      `val(dd:int64) < 2 EXP 64 - 1`] THEN
    CONJ_TAC THENL
     [CONJ_TAC THEN MATCH_MP_TAC(ARITH_RULE
      `2 EXP 64 * b + d < 2 EXP 64 * (a + 1) + c ==> a < b ==> ~(c <= d)`) THEN
      MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
      MP_TAC(SPEC `sum_s364:int64` VAL_BOUND_64) THEN ARITH_TAC;
      SIMP_TAC[BIGNUM_OF_WORDLIST_LT_MAX; LENGTH; ARITH_EQ; ARITH_SUC]] THEN
    REWRITE_TAC[GSYM NOT_ALL] THEN MP_TAC(ISPEC `dd:int64` VAL_EQ_MAX) THEN
    SIMP_TAC[VAL_BOUND_64; DIMINDEX_64; ARITH_RULE
      `a < m ==> (a < m - 1 <=> ~(a = m - 1))`] THEN
    DISCH_THEN SUBST1_TAC THEN EXPAND_TAC "dd" THEN
    REWRITE_TAC[WORD_NOT_AND; ALL; WORD_OR_EQ_0] THEN
    REWRITE_TAC[WORD_RULE `word_not d = e <=> d = word_not e`] THEN
    DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN SUBST1_TAC) THEN
    REWRITE_TAC[bignum_of_wordlist] THEN CONV_TAC WORD_REDUCE_CONV THEN
    MP_TAC(ARITH_RULE `val(sum_s391:int64) MOD 2 EXP 9 = 511 \/
                       val(sum_s391:int64) MOD 2 EXP 9 < 511`) THEN
    MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
    MP_TAC(SPEC `sum_s364:int64` VAL_BOUND_64) THEN ARITH_TAC;
    FIRST_X_ASSUM(K ALL_TAC o check (is_iff o concl))] THEN

  (*** Also evaluate h ***)

  SUBGOAL_THEN `val(h:int64) = m DIV 2 EXP 521` SUBST_ALL_TAC THENL
   [EXPAND_TAC "h" THEN REWRITE_TAC[VAL_WORD_USHR] THEN
    MATCH_MP_TAC(ARITH_RULE
     `m DIV 2 EXP 512 = x ==> x DIV 2 EXP 9 = m DIV 2 EXP 521`) THEN
    EXPAND_TAC "m" THEN CONV_TAC(LAND_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    ARITH_TAC;
    ALL_TAC] THEN

  (*** Now complete the mathematics ***)

  SUBGOAL_THEN
   `2 EXP 521 <= m MOD 2 EXP 521 + m DIV 2 EXP 521 + 1 <=>
    p_521 <= m DIV 2 EXP 521 + m MOD 2 EXP 521`
  SUBST1_TAC THENL [REWRITE_TAC[p_521] THEN ARITH_TAC; DISCH_TAC] THEN
  CONV_TAC SYM_CONV THEN MATCH_MP_TAC EQUAL_FROM_CONGRUENT_MOD_MOD THEN
  MAP_EVERY EXISTS_TAC
   [`521`;
    `if m DIV 2 EXP 521 + m MOD 2 EXP 521 < p_521
     then &(m DIV 2 EXP 521 + m MOD 2 EXP 521)
     else &(m DIV 2 EXP 521 + m MOD 2 EXP 521) - &p_521`] THEN
  REPEAT CONJ_TAC THENL
   [BOUNDER_TAC[];
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC;
    W(MP_TAC o PART_MATCH (lhand o rand) MOD_CASES o rand o lhand o snd) THEN
    ANTS_TAC THENL
     [UNDISCH_TAC `m < 2 EXP 576` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
      DISCH_THEN SUBST1_TAC] THEN
    ONCE_REWRITE_TAC[COND_RAND] THEN
    SIMP_TAC[GSYM NOT_LE; COND_SWAP; GSYM REAL_OF_NUM_SUB; COND_ID]] THEN
  ASM_REWRITE_TAC[GSYM NOT_LE; COND_SWAP] THEN
  REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN
  REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
  REWRITE_TAC[VAL_WORD_AND_MASK_WORD; bignum_of_wordlist] THEN
  ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
  REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; REAL_OF_NUM_MOD; p_521] THEN
  CONV_TAC NUM_REDUCE_CONV THEN
  COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC);;

(* ------------------------------------------------------------------------- *)
(* Instances of mul.                                                         *)
(* ------------------------------------------------------------------------- *)

let LOCAL_MUL_P521_TAC =
  ARM_MACRO_SIM_ABBREV_TAC p521_jdouble_mc 624 lvs
  `!(t:armstate) pcin pcout p3 n3 p1 n1 p2 n2.
    !a. read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) t = a
    ==>
    !b. read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) t = b
    ==>
    aligned 16 (read SP t) /\
    nonoverlapping (word pc,0x4444) (word_add (read p3 t) (word n3),72) /\
    nonoverlapping (read X26 t,216) (stackpointer,512) /\
    nonoverlapping (read X27 t,216) (stackpointer,512)
    ==> ensures arm
         (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
              read PC s = pcin /\
              read SP s = read SP t /\
              read X26 s = read X26 t /\
              read X27 s = read X27 t /\
              read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) s =
              a /\
              read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) s =
              b)
         (\s. read PC s = pcout /\
              (a < p_521 /\ b < p_521
               ==> read(memory :> bytes(word_add (read p3 t) (word n3),
                        8 * 9)) s = (a * b) MOD p_521))
         (MAYCHANGE [PC; X0; X1; X3; X4; X5; X6; X7; X8; X9;
                     X10; X11; X12; X13; X14; X15; X16; X17; X19;
                     X20; X21; X22; X23; X24; X25] ,,
          MAYCHANGE
           [memory :> bytes(word_add (read p3 t) (word n3),8 * 9)] ,,
          MAYCHANGE SOME_FLAGS)`
 (REWRITE_TAC[C_ARGUMENTS; C_RETURN; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN ASSUME_TAC) THEN

  (*** Globalize the a < p_521 /\ b < p_521 assumption for simplicity ***)

  ASM_CASES_TAC `a < p_521 /\ b < p_521` THENL
   [ASM_REWRITE_TAC[] THEN FIRST_X_ASSUM(CONJUNCTS_THEN ASSUME_TAC);
    ARM_SIM_TAC P521_JDOUBLE_EXEC (1--624)] THEN

  (*** Digitize, deduce the bound on the top words ***)

  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "y_" o lhand o concl) THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "x_" o lhand o concl) THEN
  SUBGOAL_THEN
   `a DIV 2 EXP 512 < 2 EXP 9 /\ b DIV 2 EXP 512 < 2 EXP 9`
  MP_TAC THENL
   [MAP_EVERY UNDISCH_TAC [`a < p_521`; `b < p_521`] THEN
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    MAP_EVERY EXPAND_TAC ["a"; "b"] THEN
    CONV_TAC(LAND_CONV(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV)) THEN
    STRIP_TAC] THEN

  (*** 4x4 multiplication of the low portions and its rebasing ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [5; 6; 7; 8; 10; 12; 14; 16; 17; 18; 19; 20; 21; 22; 23; 24; 25;
    26; 27; 33; 38; 40; 41; 47; 52; 54; 55; 56; 57; 58; 59; 65; 70;
    72; 73; 74; 80; 85; 87; 88; 89; 90; 91; 97; 102; 104; 105; 106;
    107; 113; 118; 120; 121; 122; 123]
   (1--133) THEN
  ABBREV_TAC
   `l = bignum_of_wordlist
         [sum_s120; sum_s121; sum_s122; sum_s123; word_shl mullo_s5 9;
          word_subword
           ((word_join:int64->int64->int128) sum_s52 mullo_s5) (55,64);
          word_subword
           ((word_join:int64->int64->int128) sum_s85 sum_s52) (55,64);
          word_subword
           ((word_join:int64->int64->int128) sum_s118 sum_s85) (55,64);
          word_ushr sum_s118 55]` THEN
  SUBGOAL_THEN
   `l < 2 EXP 521 /\
    (2 EXP 256 * l ==
     bignum_of_wordlist[x_0;x_1;x_2;x_3] *
     bignum_of_wordlist[y_0;y_1;y_2;y_3]) (mod p_521)`
  STRIP_ASSUME_TAC THENL
   [EXPAND_TAC "l" THEN CONJ_TAC THENL
     [REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
      REWRITE_TAC[BIGNUM_OF_WORDLIST_SING; VAL_WORD_USHR] THEN
      MATCH_MP_TAC(ARITH_RULE
       `x < 2 EXP (64 * 8) /\ y < 2 EXP 9
        ==> x + 2 EXP 512 * y < 2 EXP 521`) THEN
      SIMP_TAC[RDIV_LT_EQ; EXP_EQ_0; ARITH_EQ] THEN
      REWRITE_TAC[ARITH_RULE `2 EXP 55 * 2 EXP 9 = 2 EXP 64`] THEN
      REWRITE_TAC[VAL_BOUND_64] THEN
      MATCH_MP_TAC BIGNUM_OF_WORDLIST_BOUND THEN
      REWRITE_TAC[LENGTH] THEN ARITH_TAC;
      ALL_TAC] THEN
    SUBGOAL_THEN
     `bignum_of_wordlist[x_0;x_1;x_2;x_3] *
      bignum_of_wordlist[y_0;y_1;y_2;y_3] =
      bignum_of_wordlist[mullo_s5;sum_s52;sum_s85;sum_s118;
                         sum_s120;sum_s121;sum_s122;sum_s123]`
    SUBST1_TAC THENL
     [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
      ADK_48_TAC;
      ALL_TAC] THEN
    REWRITE_TAC[REAL_CONGRUENCE; p_521; ARITH_EQ] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
    REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
    REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
    REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR;
                BIT_WORD_AND; BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    ONCE_REWRITE_TAC[BIT_GUARD] THEN REWRITE_TAC[DIMINDEX_64] THEN
    CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; p_521] THEN
    REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** 4x4 multiplication of the high portions ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [138; 139; 140; 141; 143; 145; 147; 149; 150; 151; 152; 153;
    154; 155; 156; 157; 158; 159; 160; 166; 171; 173; 174; 180;
    185; 187; 188; 189; 190; 191; 192; 198; 203; 205; 206; 207;
    213; 218; 220; 221; 222; 223; 224; 230; 235; 237; 238; 239;
    240; 246; 251; 253; 254; 255; 256]
   (134--256) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist
     [mullo_s138; sum_s185; sum_s218; sum_s251;
      sum_s253; sum_s254; sum_s255; sum_s256] =
    bignum_of_wordlist[x_4;x_5;x_6;x_7] *
    bignum_of_wordlist[y_4;y_5;y_6;y_7]`
  ASSUME_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    ADK_48_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Addition combining high and low parts into hl ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [258; 259; 262; 263; 266; 267; 270; 271; 274]
   (257--275) THEN
  ABBREV_TAC
   `hl = bignum_of_wordlist
          [sum_s258; sum_s259; sum_s262; sum_s263;
           sum_s266; sum_s267; sum_s270; sum_s271; sum_s274]` THEN
  SUBGOAL_THEN
   `hl < 2 EXP 522 /\
    (2 EXP 256 * hl ==
     2 EXP 256 * bignum_of_wordlist[x_4;x_5;x_6;x_7] *
                 bignum_of_wordlist[y_4;y_5;y_6;y_7] +
     bignum_of_wordlist[x_0;x_1;x_2;x_3] *
     bignum_of_wordlist[y_0;y_1;y_2;y_3]) (mod p_521)`
  STRIP_ASSUME_TAC THENL
   [MATCH_MP_TAC(MESON[]
     `!y:num. y < e /\ P y /\ (y < e ==> y = x)
              ==> x < e /\ P x`) THEN
    EXISTS_TAC
     `bignum_of_wordlist
       [mullo_s138; sum_s185; sum_s218; sum_s251; sum_s253; sum_s254;
        sum_s255; sum_s256] + l` THEN
    REPEAT CONJ_TAC THENL
     [MATCH_MP_TAC(ARITH_RULE
       `x < 2 EXP (64 * 8) /\ y < 2 EXP 521
        ==> x + y < 2 EXP 522`) THEN
      CONJ_TAC THENL [MATCH_MP_TAC BIGNUM_OF_WORDLIST_BOUND; ALL_TAC] THEN
      ASM_REWRITE_TAC[] THEN REWRITE_TAC[LENGTH] THEN ARITH_TAC;
      ASM_REWRITE_TAC[LEFT_ADD_DISTRIB; CONG_ADD_LCANCEL_EQ];
      DISCH_THEN(fun th ->
        MATCH_MP_TAC CONG_IMP_EQ THEN EXISTS_TAC `2 EXP (64 * 9)` THEN
        CONJ_TAC THENL [MP_TAC th THEN ARITH_TAC; ALL_TAC]) THEN
      MAP_EVERY EXPAND_TAC ["hl"; "l"] THEN CONJ_TAC THENL
       [MATCH_MP_TAC BIGNUM_OF_WORDLIST_BOUND THEN
        REWRITE_TAC[LENGTH] THEN ARITH_TAC;
        ALL_TAC] THEN
      REWRITE_TAC[REAL_CONGRUENCE] THEN CONV_TAC NUM_REDUCE_CONV THEN
      REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
      ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
      DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC];
     ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN
     REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `l:num` o concl)))] THEN

  (*** The sign-magnitude difference computation ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [277; 278; 280; 281; 284; 285; 287; 288;
    291; 293; 295; 297; 299; 301; 303; 305]
   (276--306) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[WORD_UNMASK_64; WORD_XOR_MASKS]) THEN
  MAP_EVERY ABBREV_TAC
  [`sgn <=> ~(carry_s288 <=> carry_s281)`;
   `xd = bignum_of_wordlist[sum_s291; sum_s293; sum_s295; sum_s297]`;
   `yd = bignum_of_wordlist[sum_s299; sum_s301; sum_s303; sum_s305]`] THEN
  SUBGOAL_THEN
   `(&(bignum_of_wordlist[x_4;x_5;x_6;x_7]) -
     &(bignum_of_wordlist[x_0;x_1;x_2;x_3])) *
    (&(bignum_of_wordlist[y_0;y_1;y_2;y_3]) -
     &(bignum_of_wordlist[y_4;y_5;y_6;y_7])):real =
    --(&1) pow bitval sgn * &xd * &yd`
  ASSUME_TAC THENL
   [TRANS_TAC EQ_TRANS
     `(--(&1) pow bitval carry_s281 * &xd) *
      (--(&1) pow bitval carry_s288 * &yd):real` THEN
    CONJ_TAC THENL
     [ALL_TAC;
      EXPAND_TAC "sgn" THEN REWRITE_TAC[BITVAL_NOT; BITVAL_IFF] THEN
      POP_ASSUM_LIST(K ALL_TAC) THEN REWRITE_TAC[bitval] THEN
      REPEAT(COND_CASES_TAC THEN ASM_REWRITE_TAC[]) THEN
      CONV_TAC NUM_REDUCE_CONV THEN REAL_ARITH_TAC] THEN
    SUBGOAL_THEN
     `(carry_s281 <=>
       bignum_of_wordlist[x_4;x_5;x_6;x_7] <
       bignum_of_wordlist[x_0;x_1;x_2;x_3]) /\
      (carry_s288 <=>
       bignum_of_wordlist[y_0;y_1;y_2;y_3] <
       bignum_of_wordlist[y_4;y_5;y_6;y_7])`
     (CONJUNCTS_THEN SUBST_ALL_TAC)
    THENL
     [CONJ_TAC THEN MATCH_MP_TAC FLAG_FROM_CARRY_LT THEN EXISTS_TAC `256` THEN
      REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
      ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DECARRY_RULE') THEN
      REWRITE_TAC[REAL_BITVAL_NOT; REAL_VAL_WORD_MASK; DIMINDEX_64] THEN
      DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN BOUNDER_TAC[];
      ALL_TAC] THEN
    BINOP_TAC THEN REWRITE_TAC[bitval] THEN
    COND_CASES_TAC THEN ASM_REWRITE_TAC[real_pow; REAL_MUL_LID] THEN
    REWRITE_TAC[REAL_ARITH `x - y:real = --(&1) pow 1 * z <=> y - x = z`] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`256`; `&0:real`] THEN
    (CONJ_TAC THENL
      [MATCH_MP_TAC(REAL_ARITH
        `y:real <= x /\ (&0 <= x /\ x < e) /\ (&0 <= y /\ y < e)
         ==> &0 <= x - y /\ x - y < e`) THEN
       ASM_SIMP_TAC[REAL_OF_NUM_CLAUSES; LT_IMP_LE;
                    ARITH_RULE `~(a:num < b) ==> b <= a`] THEN
       REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
       CONJ_TAC THEN BOUNDER_TAC[];
       ALL_TAC] THEN
     MAP_EVERY EXPAND_TAC ["xd"; "yd"] THEN
     REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
     CONJ_TAC THENL [BOUNDER_TAC[]; REWRITE_TAC[INTEGER_CLOSED]]) THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
    ASM_REWRITE_TAC[WORD_XOR_MASK] THEN
    REWRITE_TAC[REAL_VAL_WORD_NOT; BITVAL_CLAUSES; DIMINDEX_64] THEN
    DISCH_THEN(MP_TAC o end_itlist CONJ o DESUM_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** One more 4x4 multiplication of the cross-terms ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [307; 308; 309; 310; 312; 314; 316; 318; 319; 320; 321; 322;
    323; 324; 325; 326; 327; 328; 329; 335; 340; 342; 343; 349;
    354; 356; 357; 358; 359; 360; 361; 367; 372; 374; 375; 376;
    382; 387; 389; 390; 391; 392; 393; 399; 404; 406; 407; 408;
    409; 415; 420; 422; 423; 424; 425]
   (307--425) THEN
  SUBGOAL_THEN
   `&xd * &yd:real =
    &(bignum_of_wordlist
      [mullo_s307; sum_s354; sum_s387; sum_s420; sum_s422; sum_s423; sum_s424;
       sum_s425])`
  SUBST_ALL_TAC THENL
   [MAP_EVERY EXPAND_TAC ["xd"; "yd"] THEN
    REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    ADK_48_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN
    DISCARD_MATCHING_ASSUMPTIONS [`word a = b`]] THEN
  MP_TAC(ASSUME `hl < 2 EXP 522`) THEN
  REWRITE_TAC[ARITH_RULE
   `n < 2 EXP 522 <=> n DIV 2 EXP 512 < 2 EXP 10`] THEN
  EXPAND_TAC "hl" THEN
  CONV_TAC(LAND_CONV(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV)) THEN
  DISCH_TAC THEN
  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [429; 431; 433; 435; 440; 442; 444; 446]
   (426--447) THEN
  ABBREV_TAC
   `hlm = bignum_of_wordlist
     [sum_s429; sum_s431; sum_s433; sum_s435;
      sum_s440; sum_s442; sum_s444; sum_s446;
      word_and (word_neg(word(bitval sgn))) (word 511)]` THEN
  SUBGOAL_THEN
   `(&hl +
     --(&1) pow bitval sgn *
     &(bignum_of_wordlist
       [mullo_s307; sum_s354; sum_s387; sum_s420; sum_s422; sum_s423;
        sum_s424; sum_s425]):int ==
     &2 pow 512 * &(val(sum_s274:int64) + bitval carry_s446) + &hlm)
    (mod &p_521)`
  ASSUME_TAC THENL
   [MAP_EVERY EXPAND_TAC ["hl"; "hlm"] THEN
    REWRITE_TAC[REAL_INT_CONGRUENCE; p_521; INT_OF_NUM_EQ; ARITH_EQ] THEN
    REWRITE_TAC[int_add_th; int_sub_th; int_mul_th; int_pow_th;
                int_neg_th; int_of_num_th; bignum_of_wordlist] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
    POP_ASSUM_LIST(K ALL_TAC) THEN
    REWRITE_TAC[WORD_XOR_MASK] THEN
    BOOL_CASES_TAC `sgn:bool` THEN
    ASM_REWRITE_TAC[BITVAL_CLAUSES; REAL_VAL_WORD_NOT; DIMINDEX_64] THEN
    CONV_TAC WORD_REDUCE_CONV THEN
    DISCH_THEN(MP_TAC o end_itlist CONJ o DESUM_RULE' o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN
  ABBREV_TAC `topcar:int64 = word_add sum_s274 (word(bitval carry_s446))` THEN
  SUBGOAL_THEN
   `val(sum_s274:int64) + bitval carry_s446 = val(topcar:int64) /\
    val(topcar:int64) <= 2 EXP 10`
  (CONJUNCTS_THEN2 SUBST_ALL_TAC ASSUME_TAC) THENL
   [MATCH_MP_TAC(ARITH_RULE
     `c <= 1 /\ s < 2 EXP 10 /\
      (s + c < 2 EXP 64 ==> y = s + c)
      ==> s + c = y /\ y <= 2 EXP 10`) THEN
    ASM_REWRITE_TAC[BITVAL_BOUND] THEN EXPAND_TAC "topcar" THEN
    SIMP_TAC[VAL_WORD_ADD; DIMINDEX_64; VAL_WORD_BITVAL; MOD_LT];
    ALL_TAC] THEN
  ABBREV_TAC
   `hlm' = bignum_of_wordlist
     [sum_s440; sum_s442; sum_s444; sum_s446;
      word_or (word_shl sum_s429 9)
              (word_and (word_neg (word (bitval sgn))) (word 511));
      word_subword ((word_join:int64->int64->int128) sum_s431 sum_s429) (55,64);
      word_subword ((word_join:int64->int64->int128) sum_s433 sum_s431) (55,64);
      word_subword ((word_join:int64->int64->int128) sum_s435 sum_s433) (55,64);
      word_ushr sum_s435 55]` THEN
  SUBGOAL_THEN `(2 EXP 256 * hlm' == hlm) (mod p_521)` MP_TAC THENL
   [MAP_EVERY EXPAND_TAC ["hlm"; "hlm'"] THEN
    REWRITE_TAC[REAL_CONGRUENCE; p_521; ARITH_EQ] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
     REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
    REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
    REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR; BIT_WORD_MASK;
      BIT_WORD_OR; BIT_WORD_AND; BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    ONCE_REWRITE_TAC[BIT_GUARD] THEN REWRITE_TAC[DIMINDEX_64] THEN
    CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; p_521] THEN
    REAL_INTEGER_TAC;
    FIRST_X_ASSUM(MP_TAC o
     check(can (term_match [] `(x:int == y) (mod n)` o concl))) THEN
    REWRITE_TAC[num_congruent; IMP_IMP] THEN
    REWRITE_TAC[GSYM INT_OF_NUM_POW; GSYM INT_OF_NUM_MUL] THEN
    DISCH_THEN(ASSUME_TAC o MATCH_MP (INTEGER_RULE
     `(x:int == a + y) (mod n) /\ (y' == y) (mod n)
      ==> (x == a + y') (mod n)`))] THEN
  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [448; 449; 450; 451; 455; 457; 459; 461]
   (448--463) THEN
  ABBREV_TAC
   `newtop:int64 =
    word_add (word_add (word_ushr sum_s435 55) sum_s274)
             (word (bitval carry_s461))` THEN
  SUBGOAL_THEN
   `val(word_ushr (sum_s435:int64) 55) +
    val(sum_s274:int64) + bitval carry_s461 =
    val(newtop:int64) /\
    val(newtop:int64) <= 2 EXP 11`
  STRIP_ASSUME_TAC THENL
   [MATCH_MP_TAC(ARITH_RULE
     `u < 2 EXP 9 /\ c <= 1 /\ s < 2 EXP 10 /\
      (u + s + c < 2 EXP 64 ==> y = u + s + c)
      ==> u + s + c = y /\ y <= 2 EXP 11`) THEN
    ASM_REWRITE_TAC[BITVAL_BOUND] THEN CONJ_TAC THENL
     [REWRITE_TAC[VAL_WORD_USHR] THEN
      MP_TAC(SPEC `sum_s435:int64` VAL_BOUND_64) THEN ARITH_TAC;
      EXPAND_TAC "newtop" THEN
      REWRITE_TAC[VAL_WORD_ADD; DIMINDEX_64; VAL_WORD_BITVAL] THEN
      CONV_TAC MOD_DOWN_CONV THEN SIMP_TAC[ADD_ASSOC; MOD_LT]];
    ALL_TAC] THEN
  ABBREV_TAC
   `topsum = bignum_of_wordlist
     [sum_s448; sum_s449; sum_s450; sum_s451;
      sum_s455; sum_s457; sum_s459; sum_s461; newtop]` THEN
  SUBGOAL_THEN
   `(2 EXP 512 * (2 EXP 256 * val(topcar:int64) + topsum) ==
     bignum_of_wordlist [x_0; x_1; x_2; x_3; x_4; x_5; x_6; x_7] *
     bignum_of_wordlist [y_0; y_1; y_2; y_3; y_4; y_5; y_6; y_7])
    (mod p_521)`
  MP_TAC THENL
   [REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(4,4)] THEN
    REWRITE_TAC[num_congruent; GSYM INT_OF_NUM_CLAUSES] THEN
    REWRITE_TAC[INT_ARITH
     `(l + &2 pow 256 * h) * (l' + &2 pow 256 * h'):int =
      (&1 + &2 pow 256) * (&2 pow 256 * h * h' + l * l') +
      &2 pow 256 * (h - l) * (l' - h')`] THEN
    FIRST_X_ASSUM(MP_TAC o
     check(can (term_match [] `x:real = a pow n * y`) o concl)) THEN
    REWRITE_TAC[GSYM int_of_num_th; GSYM int_pow_th; GSYM int_mul_th;
                GSYM int_sub_th; GSYM int_add_th; GSYM int_neg_th] THEN
    REWRITE_TAC[GSYM int_eq] THEN DISCH_THEN SUBST1_TAC THEN
    FIRST_X_ASSUM(MP_TAC o GEN_REWRITE_RULE I [num_congruent]) THEN
    REWRITE_TAC[GSYM INT_OF_NUM_CLAUSES] THEN MATCH_MP_TAC(INTEGER_RULE
     `(a:int == b * x' + c) (mod n)
      ==> (x' == x) (mod n)
          ==> (a == b * x + c) (mod n)`) THEN
    FIRST_X_ASSUM(MATCH_MP_TAC o MATCH_MP (INTEGER_RULE
     `(hl + m:int == tc + e * hlm) (mod n)
      ==> (x == e * e * hl + e * tc + e * e * hlm) (mod n)
          ==> (x == (&1 + e) * e * hl + e * m) (mod n)`)) THEN
    REWRITE_TAC[INT_ARITH `(&2:int) pow 512 = &2 pow 256 * &2 pow 256`] THEN
    REWRITE_TAC[GSYM INT_MUL_ASSOC; GSYM INT_ADD_LDISTRIB] THEN
    MATCH_MP_TAC(INTEGER_RULE
     `hl + hlm:int = s
      ==> (e * e * (tc + s) == e * e * (hl + tc + hlm)) (mod n)`) THEN
    REWRITE_TAC[INT_OF_NUM_CLAUSES] THEN EXPAND_TAC "topsum" THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN FIRST_X_ASSUM(fun th ->
      GEN_REWRITE_TAC (funpow 3 RAND_CONV) [SYM th]) THEN
    MAP_EVERY EXPAND_TAC ["hl"; "hlm'"] THEN
    REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_ARITH_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN
    DISCARD_MATCHING_ASSUMPTIONS
     [`(a:int == b) (mod n)`; `(a:num == b) (mod n)`; `x:real = y`;
      `a:num = b * c`; `word_add a b = c`] THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `hl:num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `hlm':num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `sgn:bool` o concl))) THEN
    DISCH_TAC] THEN

  (*** The intricate augmentation of the product with top words ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [484; 498; 510; 527; 551; 566; 579; 590; 595]
   (464--595) THEN
  SUBGOAL_THEN
   `(a * b) MOD p_521 =
    (2 EXP 512 *
     (2 EXP 512 * val(x_8:int64) * val(y_8:int64) +
      val x_8 * bignum_of_wordlist[y_0;y_1;y_2;y_3;y_4;y_5;y_6;y_7] +
      val y_8 * bignum_of_wordlist[x_0;x_1;x_2;x_3;x_4;x_5;x_6;x_7] +
      2 EXP 256 * val(topcar:int64) + topsum)) MOD p_521`
  SUBST1_TAC THENL
   [ONCE_REWRITE_TAC[ARITH_RULE
     `e * (e * h + x + y + z):num = e * (e * h + x + y) + e * z`] THEN
    ONCE_REWRITE_TAC[GSYM MOD_ADD_MOD] THEN
    FIRST_X_ASSUM(SUBST1_TAC o GEN_REWRITE_RULE I [CONG]) THEN
    CONV_TAC MOD_DOWN_CONV THEN AP_THM_TAC THEN AP_TERM_TAC THEN
    MAP_EVERY EXPAND_TAC ["a"; "b"] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN ARITH_TAC;
    FIRST_X_ASSUM(K ALL_TAC o GEN_REWRITE_RULE I [CONG])] THEN
  SUBGOAL_THEN
   `2 EXP 512 * val(x_8:int64) * val(y_8:int64) +
    val x_8 * bignum_of_wordlist[y_0;y_1;y_2;y_3;y_4;y_5;y_6;y_7] +
    val y_8 * bignum_of_wordlist[x_0;x_1;x_2;x_3;x_4;x_5;x_6;x_7] +
    2 EXP 256 * val(topcar:int64) + topsum =
    bignum_of_wordlist
     [sum_s484; sum_s498; sum_s510; sum_s527;
      sum_s551; sum_s566; sum_s579; sum_s590; sum_s595]`
  SUBST1_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_EQ] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN
    CONJ_TAC THENL
     [REWRITE_TAC[REAL_OF_NUM_CLAUSES; LE_0] THEN
      MATCH_MP_TAC(ARITH_RULE
       `c2 <= 2 EXP 9 * 2 EXP 9 /\
        x <= 2 EXP 9 * 2 EXP 512 /\ y <= 2 EXP 9 * 2 EXP 512 /\
        c <= 2 EXP 256 * 2 EXP 64 /\
        s < 2 EXP 512 * 2 EXP 11 + 2 EXP 512
        ==> 2 EXP 512 * c2 + x + y + c + s < 2 EXP 576`) THEN
      REPEAT CONJ_TAC THEN
      TRY(MATCH_MP_TAC LE_MULT2 THEN
          ASM_SIMP_TAC[LT_IMP_LE; LE_REFL; VAL_BOUND_64] THEN
          REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
          BOUNDER_TAC[]) THEN
      EXPAND_TAC "topsum" THEN
      REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
      MATCH_MP_TAC(ARITH_RULE
       `c <= 2 EXP 11 /\ s < 2 EXP 512
        ==> s + 2 EXP 512 * c < 2 EXP 512 * 2 EXP 11 + 2 EXP 512`) THEN
      ASM_REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN
      REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
      BOUNDER_TAC[];
      ALL_TAC] THEN
    CONJ_TAC THENL
     [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
      BOUNDER_TAC[];
      REWRITE_TAC[INTEGER_CLOSED]] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ) THEN
    REWRITE_TAC[DIMINDEX_64; ADD_CLAUSES] THEN
    CONV_TAC(ONCE_DEPTH_CONV NUM_MOD_CONV) THEN
    SUBST1_TAC(SYM(NUM_REDUCE_CONV `2 EXP 52 - 1`)) THEN
    REWRITE_TAC[WORD_RULE
     `word_add (word(val(x:int64) * val(d:int64)))
               (word(val(y:int64) * val(e:int64))):int64 =
      word(val x * val d + val y * val e)`] THEN
    REWRITE_TAC[WORD_RULE
     `word_add (word x) (word_shl c 48):int64 =
      word(2 EXP 48 * val c + x)`] THEN
    MAP_EVERY ABBREV_TAC
     [`dx0:int64 = word_and x_0 (word (2 EXP 52 - 1))`;
      `dx1:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) x_1 x_0) (52,64))
                           (word (2 EXP 52 - 1))`;
      `dx2:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) x_2 x_1) (40,64))
                           (word (2 EXP 52 - 1))`;
      `dx3:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) x_3 x_2) (28,64))
                           (word (2 EXP 52 - 1))`;
      `dx4:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) x_4 x_3) (16,64))
                           (word (2 EXP 52 - 1))`;
      `dx5:int64 = word_and (word_ushr x_4 4) (word (2 EXP 52 - 1))`;
      `dx6:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) x_5 x_4) (56,64))
                           (word (2 EXP 52 - 1))`;
      `dx7:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) x_6 x_5) (44,64))
                           (word (2 EXP 52 - 1))`;
      `dx8:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) x_7 x_6) (32,64))
                           (word (2 EXP 52 - 1))`;
      `dx9:int64 = word_ushr x_7 20`;
      `dy0:int64 = word_and y_0 (word (2 EXP 52 - 1))`;
      `dy1:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) y_1 y_0) (52,64))
                           (word (2 EXP 52 - 1))`;
      `dy2:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) y_2 y_1) (40,64))
                           (word (2 EXP 52 - 1))`;
      `dy3:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) y_3 y_2) (28,64))
                           (word (2 EXP 52 - 1))`;
      `dy4:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) y_4 y_3) (16,64))
                           (word (2 EXP 52 - 1))`;
      `dy5:int64 = word_and (word_ushr y_4 4) (word (2 EXP 52 - 1))`;
      `dy6:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) y_5 y_4) (56,64))
                           (word (2 EXP 52 - 1))`;
      `dy7:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) y_6 y_5) (44,64))
                           (word (2 EXP 52 - 1))`;
      `dy8:int64 = word_and
        (word_subword ((word_join:int64->int64->int128) y_7 y_6) (32,64))
                           (word (2 EXP 52 - 1))`;
      `dy9:int64 = word_ushr y_7 20`;
      `e0:int64 = word(val(y_8:int64) * val(dx0:int64) +
                       val(x_8:int64) * val(dy0:int64))`;
      `e1:int64 =
       word_add (word(val(y_8:int64) * val(dx1:int64) +
                      val(x_8:int64) * val(dy1:int64)))
                (word_ushr e0 52)`;
      `e2:int64 =
       word_add (word(val(y_8:int64) * val(dx2:int64) +
                      val(x_8:int64) * val(dy2:int64)))
                (word_ushr e1 52)`;
      `e3:int64 =
       word_add (word(val(y_8:int64) * val(dx3:int64) +
                      val(x_8:int64) * val(dy3:int64)))
                (word_ushr e2 52)`;
      `e4:int64 =
       word_add (word(2 EXP 48 * val(topcar:int64) +
                      val(y_8:int64) * val(dx4:int64) +
                      val(x_8:int64) * val(dy4:int64)))
                (word_ushr e3 52)`;
      `e5:int64 =
       word_add (word(val(y_8:int64) * val(dx5:int64) +
                      val(x_8:int64) * val(dy5:int64)))
                (word_ushr e4 52)`;
      `e6:int64 =
       word_add (word(val(y_8:int64) * val(dx6:int64) +
                      val(x_8:int64) * val(dy6:int64)))
                (word_ushr e5 52)`;
      `e7:int64 =
       word_add (word(val(y_8:int64) * val(dx7:int64) +
                      val(x_8:int64) * val(dy7:int64)))
                (word_ushr e6 52)`;
      `e8:int64 =
       word_add (word(val(y_8:int64) * val(dx8:int64) +
                      val(x_8:int64) * val(dy8:int64)))
                (word_ushr e7 52)`;
      `e9:int64 =
       word_add (word(val(y_8:int64) * val(dx9:int64) +
                      val(x_8:int64) * val(dy9:int64)))
                (word_ushr e8 52)`;
      `f0:int64 = word_subword
       ((word_join:int64->int64->int128) e1 (word_shl e0 12)) (12,64)`;
      `f1:int64 = word_subword
       ((word_join:int64->int64->int128) e2 (word_shl e1 12)) (24,64)`;
      `f2:int64 = word_subword
       ((word_join:int64->int64->int128) e3 (word_shl e2 12)) (36,64)`;
      `f3:int64 = word_subword
       ((word_join:int64->int64->int128) e4 (word_shl e3 12)) (48,64)`;
      `f4:int64 = word_subword
        ((word_join:int64->int64->int128) e6
        (word_shl (word_subword ((word_join:int64->int64->int128) e5
              (word_shl e4 12)) (60,64)) 8)) (8,64)`;
      `f5:int64 = word_subword
       ((word_join:int64->int64->int128) e7 (word_shl e6 12)) (20,64)`;
      `f6:int64 = word_subword
        ((word_join:int64->int64->int128) e8 (word_shl e7 12)) (32,64)`;
      `f7:int64 = word_subword
        ((word_join:int64->int64->int128) e9 (word_shl e8 12)) (44,64)`;
      `f8:int64 = word_ushr e9 44`] THEN
    SUBGOAL_THEN
     `val(x_8:int64) * bignum_of_wordlist [y_0;y_1;y_2;y_3;y_4;y_5;y_6;y_7] +
      val(y_8:int64) * bignum_of_wordlist [x_0;x_1;x_2;x_3;x_4;x_5;x_6;x_7] +
      2 EXP 256 * val(topcar:int64) + topsum =
      bignum_of_wordlist[f0;f1;f2;f3;f4;f5;f6;f7;f8] + topsum`
    SUBST1_TAC THENL
     [SUBGOAL_THEN
       `bignum_of_wordlist[x_0; x_1; x_2; x_3; x_4; x_5; x_6; x_7] =
        ITLIST (\(h:int64) t. val h + 2 EXP 52 * t)
               [dx0;dx1;dx2;dx3;dx4;dx5;dx6;dx7;dx8;dx9] 0 /\
        bignum_of_wordlist[y_0; y_1; y_2; y_3; y_4; y_5; y_6; y_7] =
        ITLIST (\(h:int64) t. val h + 2 EXP 52 * t)
               [dy0;dy1;dy2;dy3;dy4;dy5;dy6;dy7;dy8;dy9] 0 /\
        bignum_of_wordlist[f0; f1; f2; f3; f4; f5; f6; f7; f8] =
        2 EXP 520 * val(e9:int64) DIV 2 EXP 52 +
        ITLIST (\(h:int64) t. val h MOD 2 EXP 52 + 2 EXP 52 * t)
               [e0; e1; e2; e3; e4; e5; e6; e7; e8; e9] 0`
      (REPEAT_TCL CONJUNCTS_THEN SUBST1_TAC) THENL
       [REWRITE_TAC[ITLIST; ADD_CLAUSES; MULT_CLAUSES; bignum_of_wordlist] THEN
        REWRITE_TAC[GSYM VAL_WORD_USHR; GSYM VAL_WORD_AND_MASK_WORD] THEN
        REPEAT CONJ_TAC THENL
         [MAP_EVERY EXPAND_TAC
           ["dx0";"dx1";"dx2";"dx3";"dx4";"dx5";"dx6";"dx7";"dx8";"dx9"];
          MAP_EVERY EXPAND_TAC
           ["dy0";"dy1";"dy2";"dy3";"dy4";"dy5";"dy6";"dy7";"dy8";"dy9"];
          MAP_EVERY EXPAND_TAC
           ["f0";"f1";"f2";"f3";"f4";"f5";"f6";"f7";"f8"]] THEN
        CONV_TAC NUM_REDUCE_CONV THEN
        REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
        REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
        REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
        REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR;
                    BIT_WORD_AND; BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
        CONV_TAC NUM_REDUCE_CONV THEN
        CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
        CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
        CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
        ONCE_REWRITE_TAC[BIT_GUARD] THEN REWRITE_TAC[DIMINDEX_64] THEN
        CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
        CONV_TAC NUM_RING;
        ALL_TAC] THEN
      SUBGOAL_THEN
       `val(y_8:int64) * val(dx0:int64) + val(x_8:int64) * val(dy0:int64) =
        val (e0:int64) /\
        val(y_8:int64) * val(dx1:int64) + val(x_8:int64) * val(dy1:int64) +
        val e0 DIV 2 EXP 52 = val(e1:int64) /\
        val(y_8:int64) * val(dx2:int64) + val(x_8:int64) * val(dy2:int64) +
        val e1 DIV 2 EXP 52 = val(e2:int64) /\
        val(y_8:int64) * val(dx3:int64) + val(x_8:int64) * val(dy3:int64) +
        val e2 DIV 2 EXP 52 = val(e3:int64) /\
        2 EXP 48 * val(topcar:int64) +
        val(y_8:int64) * val(dx4:int64) + val(x_8:int64) * val(dy4:int64) +
        val e3 DIV 2 EXP 52 = val(e4:int64) /\
        val(y_8:int64) * val(dx5:int64) + val(x_8:int64) * val(dy5:int64) +
        val e4 DIV 2 EXP 52 = val(e5:int64) /\
        val(y_8:int64) * val(dx6:int64) + val(x_8:int64) * val(dy6:int64) +
        val e5 DIV 2 EXP 52 = val(e6:int64) /\
        val(y_8:int64) * val(dx7:int64) + val(x_8:int64) * val(dy7:int64) +
        val e6 DIV 2 EXP 52 = val(e7:int64) /\
        val(y_8:int64) * val(dx8:int64) + val(x_8:int64) * val(dy8:int64) +
        val e7 DIV 2 EXP 52 = val(e8:int64) /\
        val(y_8:int64) * val(dx9:int64) + val(x_8:int64) * val(dy9:int64) +
        val e8 DIV 2 EXP 52 = val(e9:int64)`
      MP_TAC THENL [ALL_TAC; REWRITE_TAC[ITLIST] THEN ARITH_TAC] THEN
      REPEAT CONJ_TAC THEN FIRST_X_ASSUM(fun th ->
        GEN_REWRITE_TAC (RAND_CONV o RAND_CONV) [SYM th]) THEN
      REWRITE_TAC[VAL_WORD_ADD; VAL_WORD; VAL_WORD_USHR; DIMINDEX_64] THEN
      CONV_TAC SYM_CONV THEN CONV_TAC MOD_DOWN_CONV THEN
      REWRITE_TAC[GSYM ADD_ASSOC] THEN MATCH_MP_TAC MOD_LT THEN
      (MATCH_MP_TAC(ARITH_RULE
        `c <= 2 EXP 10 /\ x < 2 EXP 63 ==> 2 EXP 48 * c + x < 2 EXP 64`) ORELSE
       MATCH_MP_TAC(ARITH_RULE `x < 2 EXP 63 ==> x < 2 EXP 64`)) THEN
      ASM_REWRITE_TAC[] THEN
      (MATCH_MP_TAC(ARITH_RULE
        `n * d <= 2 EXP 9 * 2 EXP 52 /\
         m * e <= 2 EXP 9 * 2 EXP 52 /\
         f < 2 EXP 64
         ==> n * d + m * e + f DIV 2 EXP 52 < 2 EXP 63`) ORELSE
       MATCH_MP_TAC(ARITH_RULE
        `n * d <= 2 EXP 9 * 2 EXP 52 /\
         m * e <= 2 EXP 9 * 2 EXP 52
         ==> n * d + m * e < 2 EXP 63`)) THEN
      REWRITE_TAC[VAL_BOUND_64] THEN CONJ_TAC THEN
      MATCH_MP_TAC LE_MULT2 THEN
      CONJ_TAC THEN MATCH_MP_TAC LT_IMP_LE THEN ASM_REWRITE_TAC[] THEN
      MAP_EVERY EXPAND_TAC
       ["dx0";"dx1";"dx2";"dx3";"dx4";"dx5";"dx6";"dx7";"dx8";"dx9";
        "dy0";"dy1";"dy2";"dy3";"dy4";"dy5";"dy6";"dy7";"dy8";"dy9"] THEN
      REWRITE_TAC[VAL_WORD_AND_MASK_WORD] THEN TRY ARITH_TAC THEN
      REWRITE_TAC[VAL_WORD_USHR] THEN MATCH_MP_TAC
       (ARITH_RULE `n < 2 EXP 64 ==> n DIV 2 EXP 20 < 2 EXP 52`) THEN
      MATCH_ACCEPT_TAC VAL_BOUND_64;
      ALL_TAC] THEN
    REWRITE_TAC[VAL_WORD_ADD; VAL_WORD; DIMINDEX_64] THEN
    CONV_TAC MOD_DOWN_CONV THEN
    REWRITE_TAC[REAL_OF_NUM_MOD; GSYM REAL_OF_NUM_CLAUSES] THEN
    EXPAND_TAC "topsum" THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    DISCH_THEN(MP_TAC o end_itlist CONJ o DESUM_RULE' o rev o CONJUNCTS) THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** The final modular reduction ***)

  ABBREV_TAC
   `n = bignum_of_wordlist
         [sum_s484; sum_s498; sum_s510; sum_s527; sum_s551; sum_s566;
          sum_s579; sum_s590; sum_s595]` THEN

  SUBGOAL_THEN `n < 2 EXP 576` ASSUME_TAC THENL
   [EXPAND_TAC "n" THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    BOUNDER_TAC[];
    ALL_TAC] THEN
  ONCE_REWRITE_TAC[GSYM MOD_MULT_MOD2] THEN
  SUBGOAL_THEN `n MOD p_521 = (n DIV 2 EXP 521 + n MOD 2 EXP 521) MOD p_521`
  SUBST1_TAC THENL
   [GEN_REWRITE_TAC (LAND_CONV o LAND_CONV)
     [ARITH_RULE `n = 2 EXP 521 * n DIV 2 EXP 521 + n MOD 2 EXP 521`] THEN
    REWRITE_TAC[GSYM CONG] THEN MATCH_MP_TAC(NUMBER_RULE
     `(e == 1) (mod p) ==> (e * h + l == h + l) (mod p)`) THEN
    REWRITE_TAC[p_521; CONG] THEN ARITH_TAC;
    ALL_TAC] THEN
  SUBGOAL_THEN `n DIV 2 EXP 521 < 2 EXP 64 /\ n MOD 2 EXP 521 < 2 EXP 521`
  STRIP_ASSUME_TAC THENL
   [REWRITE_TAC[MOD_LT_EQ] THEN UNDISCH_TAC `n < 2 EXP 576` THEN ARITH_TAC;
    ALL_TAC] THEN
  ARM_STEPS_TAC P521_JDOUBLE_EXEC (596--598) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[GSYM WORD_AND_ASSOC; DIMINDEX_64;
      NUM_REDUCE_CONV `9 MOD 64`]) THEN
  MAP_EVERY ABBREV_TAC
   [`h:int64 = word_ushr sum_s595 9`;
    `d:int64 = word_or sum_s595 (word 18446744073709551104)`;
    `dd:int64 =
      word_and sum_s498 (word_and sum_s510 (word_and sum_s527
       (word_and sum_s551 (word_and sum_s566
         (word_and sum_s579 sum_s590)))))`] THEN
  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (599--601) (599--601) THEN
  SUBGOAL_THEN
   `carry_s601 <=>
    2 EXP 192 <=
      2 EXP 128 * val(d:int64) + 2 EXP 64 * val(dd:int64) +
      val(h:int64) + val(sum_s484:int64) + 1`
  (ASSUME_TAC o SYM) THENL
   [MATCH_MP_TAC FLAG_FROM_CARRY_LE THEN EXISTS_TAC `192` THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DECARRY_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN BOUNDER_TAC[];
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN
  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (602--610) (602--610) THEN
  SUBGOAL_THEN
   `val(d:int64) = 2 EXP 9 * (2 EXP 55 - 1) + val(sum_s595:int64) MOD 2 EXP 9`
  SUBST_ALL_TAC THENL
   [EXPAND_TAC "d" THEN ONCE_REWRITE_TAC[WORD_BITWISE_RULE
     `word_or a b = word_or b (word_and a (word_not b))`] THEN
    SIMP_TAC[VAL_WORD_OR_DISJOINT; WORD_BITWISE_RULE
     `word_and x (word_and y (word_not x)) = word 0`] THEN
    REWRITE_TAC[GSYM VAL_WORD_AND_MASK_WORD] THEN
    CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC WORD_REDUCE_CONV;
    ALL_TAC] THEN
  SUBGOAL_THEN
   `2 EXP 512 * val(sum_s595:int64) MOD 2 EXP 9 +
    bignum_of_wordlist
     [sum_s484; sum_s498; sum_s510; sum_s527;
      sum_s551; sum_s566; sum_s579; sum_s590] =
    n MOD 2 EXP 521`
  (LABEL_TAC "*") THENL
   [CONV_TAC SYM_CONV THEN EXPAND_TAC "n" THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    REWRITE_TAC[ARITH_RULE `2 EXP 521 = 2 EXP 512 * 2 EXP 9`] THEN
    REWRITE_TAC[SYM(NUM_REDUCE_CONV `64 * 8`)] THEN
    SIMP_TAC[LENGTH; ARITH_LT; ARITH_LE; MOD_MULT_MOD; ADD_CLAUSES;
             ARITH_SUC; BIGNUM_OF_WORDLIST_BOUND; MOD_LT; DIV_LT;
             MOD_MULT_ADD; DIV_MULT_ADD; EXP_EQ_0; ARITH_EQ] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN ARITH_TAC;
    ALL_TAC] THEN
  SUBGOAL_THEN
   `2 EXP 521 <= n MOD 2 EXP 521 + val(h:int64) + 1 <=> carry_s601`
  MP_TAC THENL
   [REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN EXPAND_TAC "carry_s601" THEN
    ONCE_REWRITE_TAC[bignum_of_wordlist] THEN
    MATCH_MP_TAC(TAUT
     `!p q. ((p ==> ~r) /\ (q ==> ~s)) /\ (p <=> q) /\ (~p /\ ~q ==> (r <=> s))
            ==> (r <=> s)`) THEN
    MAP_EVERY EXISTS_TAC
     [`bignum_of_wordlist
        [sum_s498; sum_s510; sum_s527; sum_s551; sum_s566; sum_s579; sum_s590] <
       2 EXP (64 * 7) - 1`;
      `val(dd:int64) < 2 EXP 64 - 1`] THEN
    CONJ_TAC THENL
     [CONJ_TAC THEN MATCH_MP_TAC(ARITH_RULE
      `2 EXP 64 * b + d < 2 EXP 64 * (a + 1) + c ==> a < b ==> ~(c <= d)`) THEN
      MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
      MP_TAC(SPEC `sum_s484:int64` VAL_BOUND_64) THEN ARITH_TAC;
      SIMP_TAC[BIGNUM_OF_WORDLIST_LT_MAX; LENGTH; ARITH_EQ; ARITH_SUC]] THEN
    REWRITE_TAC[GSYM NOT_ALL] THEN MP_TAC(ISPEC `dd:int64` VAL_EQ_MAX) THEN
    SIMP_TAC[VAL_BOUND_64; DIMINDEX_64; ARITH_RULE
      `a < n ==> (a < n - 1 <=> ~(a = n - 1))`] THEN
    DISCH_THEN SUBST1_TAC THEN SUBST1_TAC(SYM(ASSUME
     `word_and sum_s498 (word_and sum_s510 (word_and sum_s527
      (word_and sum_s551 (word_and sum_s566 (word_and sum_s579 sum_s590))))) =
      (dd:int64)`)) THEN
    REWRITE_TAC[WORD_NOT_AND; ALL; WORD_OR_EQ_0] THEN
    REWRITE_TAC[WORD_RULE `word_not d = e <=> d = word_not e`] THEN
    DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN SUBST1_TAC) THEN
    REWRITE_TAC[bignum_of_wordlist] THEN CONV_TAC WORD_REDUCE_CONV THEN
    MP_TAC(ARITH_RULE `val(sum_s595:int64) MOD 2 EXP 9 = 511 \/
                       val(sum_s595:int64) MOD 2 EXP 9 < 511`) THEN
    MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
    MP_TAC(SPEC `sum_s484:int64` VAL_BOUND_64) THEN ARITH_TAC;
    FIRST_X_ASSUM(K ALL_TAC o check (is_iff o concl))] THEN
  SUBGOAL_THEN `val(h:int64) = n DIV 2 EXP 521` SUBST_ALL_TAC THENL
   [SUBST1_TAC(SYM(ASSUME `word_ushr sum_s595 9 = (h:int64)`)) THEN
    REWRITE_TAC[VAL_WORD_USHR] THEN
    MATCH_MP_TAC(ARITH_RULE
     `m DIV 2 EXP 512 = x ==> x DIV 2 EXP 9 = m DIV 2 EXP 521`) THEN
    EXPAND_TAC "n" THEN CONV_TAC(LAND_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    ARITH_TAC;
    ALL_TAC] THEN
  SUBGOAL_THEN
   `2 EXP 521 <= n MOD 2 EXP 521 + n DIV 2 EXP 521 + 1 <=>
    p_521 <= n DIV 2 EXP 521 + n MOD 2 EXP 521`
  SUBST1_TAC THENL [REWRITE_TAC[p_521] THEN ARITH_TAC; DISCH_TAC] THEN
  SUBGOAL_THEN `(n DIV 2 EXP 521 + n MOD 2 EXP 521) MOD p_521 < p_521`
  MP_TAC THENL [REWRITE_TAC[MOD_LT_EQ; p_521] THEN ARITH_TAC; ALL_TAC] THEN
  SUBGOAL_THEN
   `(n DIV 2 EXP 521 + n MOD 2 EXP 521) MOD p_521 =
    bignum_of_wordlist
     [sum_s602; sum_s603; sum_s604; sum_s605; sum_s606;
      sum_s607; sum_s608; sum_s609; word_and sum_s610 (word(2 EXP 9 - 1))]`
  SUBST1_TAC THENL
   [MATCH_MP_TAC EQUAL_FROM_CONGRUENT_MOD_MOD THEN
    MAP_EVERY EXISTS_TAC
     [`521`;
      `if n DIV 2 EXP 521 + n MOD 2 EXP 521 < p_521
       then &(n DIV 2 EXP 521 + n MOD 2 EXP 521)
       else &(n DIV 2 EXP 521 + n MOD 2 EXP 521) - &p_521`] THEN
    REPEAT CONJ_TAC THENL
     [BOUNDER_TAC[];
      REWRITE_TAC[p_521] THEN ARITH_TAC;
      REWRITE_TAC[p_521] THEN ARITH_TAC;
      ALL_TAC;
      W(MP_TAC o PART_MATCH (lhand o rand) MOD_CASES o rand o lhand o snd) THEN
      ANTS_TAC THENL
       [UNDISCH_TAC `n < 2 EXP 576` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
        DISCH_THEN SUBST1_TAC] THEN
      ONCE_REWRITE_TAC[COND_RAND] THEN
      SIMP_TAC[GSYM NOT_LE; COND_SWAP; GSYM REAL_OF_NUM_SUB; COND_ID]] THEN
    ASM_REWRITE_TAC[GSYM NOT_LE; COND_SWAP] THEN
    REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN
    REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
    REWRITE_TAC[VAL_WORD_AND_MASK_WORD; bignum_of_wordlist] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; REAL_OF_NUM_MOD; p_521] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN DISCH_TAC] THEN

  (*** The rotation to shift from the 512 position ***)

  ARM_STEPS_TAC P521_JDOUBLE_EXEC (611--624) THEN
  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN
  CONV_TAC MOD_DOWN_CONV THEN CONV_TAC SYM_CONV THEN
  REWRITE_TAC[MOD_UNIQUE] THEN
  CONV_TAC(ONCE_DEPTH_CONV BIGNUM_LEXPAND_CONV) THEN
   UNDISCH_TAC
   `bignum_of_wordlist
     [sum_s602; sum_s603; sum_s604; sum_s605; sum_s606;
      sum_s607; sum_s608; sum_s609; word_and sum_s610 (word(2 EXP 9 - 1))]
    < p_521` THEN
  REWRITE_TAC[BIGNUM_FROM_MEMORY_LT_P521; bignum_of_wordlist] THEN
  ASM_REWRITE_TAC[DIMINDEX_64; BIT_WORD_AND; BIT_WORD] THEN
  CONV_TAC(ONCE_DEPTH_CONV EXPAND_CASES_CONV) THEN
  CONV_TAC NUM_REDUCE_CONV THEN
  DISCH_THEN (LABEL_TAC "*" o CONV_RULE(RAND_CONV CONJ_CANON_CONV)) THEN
  REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
  REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
  REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
  REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_AND; BIT_WORD;
              BIT_WORD_USHR; BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
  CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
  CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
  CONV_TAC(LAND_CONV(RAND_CONV(RAND_CONV CONJ_CANON_CONV))) THEN
  ASM_REWRITE_TAC[] THEN REWRITE_TAC[p_521] THEN
  CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[REAL_CONGRUENCE] THEN
  CONV_TAC NUM_REDUCE_CONV THEN REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
  REAL_INTEGER_TAC);;

(* ------------------------------------------------------------------------- *)
(* Instances of add.                                                         *)
(* ------------------------------------------------------------------------- *)

let LOCAL_ADD_P521_TAC =
  ARM_MACRO_SIM_ABBREV_TAC p521_jdouble_mc 37 lvs
  `!(t:armstate) pcin pcout p3 n3 p1 n1 p2 n2.
    !m. read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) t = m
    ==>
    !n. read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) t = n
    ==>
    aligned 16 (read SP t) /\
    nonoverlapping (word pc,0x4444) (word_add (read p3 t) (word n3),72)
    ==> ensures arm
         (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
              read PC s = pcin /\
              read SP s = read SP t /\
              read X26 s = read X26 t /\
              read X27 s = read X27 t /\
              read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) s =
              m /\
              read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) s =
              n)
         (\s. read PC s = pcout /\
              (m < p_521 /\ n < p_521
               ==> read(memory :> bytes(word_add (read p3 t) (word n3),
                     8 * 9)) s = (m + n) MOD p_521))
         (MAYCHANGE [PC; X3; X4; X5; X6; X7; X8; X9; X10; X11; X12; X13] ,,
          MAYCHANGE
           [memory :> bytes(word_add (read p3 t) (word n3),8 * 9)] ,,
          MAYCHANGE SOME_FLAGS)`
 (REWRITE_TAC[C_ARGUMENTS; C_RETURN; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN ASSUME_TAC) THEN

  (*** Globalize the m < p_521 /\ n < p_521 assumption ***)

  ASM_CASES_TAC `m < p_521 /\ n < p_521` THENL
   [ASM_REWRITE_TAC[] THEN FIRST_X_ASSUM(CONJUNCTS_THEN ASSUME_TAC);
    ARM_SIM_TAC P521_JDOUBLE_EXEC (1--37)] THEN
  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN
  FIRST_ASSUM(BIGNUM_DIGITIZE_TAC "n_" o lhand o concl) THEN
  FIRST_ASSUM(BIGNUM_DIGITIZE_TAC "m_" o lhand o concl) THEN

  (*** Initial non-overflowing addition s = x + y + 1 ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC [4;5;8;9;12;13;16;17;20] (1--20) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist
     [sum_s4;sum_s5;sum_s8;sum_s9;sum_s12;sum_s13;sum_s16;sum_s17;sum_s20] =
    m + n + 1`
  ASSUME_TAC THENL
   [REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN
    CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC] THEN
    CONJ_TAC THENL
     [MAP_EVERY UNDISCH_TAC [`m < p_521`; `n < p_521`] THEN
      REWRITE_TAC[GSYM REAL_OF_NUM_LT; GSYM REAL_OF_NUM_ADD] THEN
      REWRITE_TAC[p_521] THEN REAL_ARITH_TAC;
      REWRITE_TAC[INTEGER_CLOSED]] THEN
    MAP_EVERY EXPAND_TAC ["m"; "n"] THEN
    REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** The net comparison s >= 2^521 <=> x + y >= p_521 ***)

  ARM_STEPS_TAC P521_JDOUBLE_EXEC (21--22) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[WORD_UNMASK_64; NOT_LT]) THEN
  SUBGOAL_THEN `512 <= val(sum_s20:int64) <=> p_521 <= m + n`
  SUBST_ALL_TAC THENL
   [TRANS_TAC EQ_TRANS `512 <= (m + n + 1) DIV 2 EXP 512` THEN
    CONJ_TAC THENL [ALL_TAC; REWRITE_TAC[p_521] THEN ARITH_TAC] THEN
    FIRST_X_ASSUM(fun th ->
      GEN_REWRITE_TAC (RAND_CONV o RAND_CONV o LAND_CONV) [SYM th]) THEN
    CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    REWRITE_TAC[];
    ALL_TAC] THEN

  (*** The final optional subtraction of either 1 or 2^521 ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (23::(25--32)) (23--37) THEN
  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN
  CONV_TAC SYM_CONV THEN CONV_TAC(RAND_CONV BIGNUM_LEXPAND_CONV) THEN
  ASM_REWRITE_TAC[] THEN MATCH_MP_TAC EQUAL_FROM_CONGRUENT_MOD_MOD THEN
  MAP_EVERY EXISTS_TAC
   [`64 * 9`;
    `if p_521 <= m + n then &(m + n + 1) - &2 pow 521
     else &(m + n + 1) - &1:real`] THEN
  REPEAT CONJ_TAC THENL
   [MATCH_MP_TAC BIGNUM_OF_WORDLIST_BOUND THEN
    REWRITE_TAC[LENGTH] THEN ARITH_TAC;
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC;
    ASM_SIMP_TAC[MOD_ADD_CASES; GSYM NOT_LE; COND_SWAP] THEN
    COND_CASES_TAC THEN ASM_SIMP_TAC[GSYM REAL_OF_NUM_SUB] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; p_521] THEN REAL_ARITH_TAC] THEN
  ABBREV_TAC `s = m + n + 1` THEN POP_ASSUM(K ALL_TAC) THEN EXPAND_TAC "s" THEN
  ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
  REWRITE_TAC[WORD_AND_MASK; GSYM NOT_LE] THEN
  REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
  COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
  CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC WORD_REDUCE_CONV THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC);;

(* ------------------------------------------------------------------------- *)
(* Instances of sub.                                                         *)
(* ------------------------------------------------------------------------- *)

let LOCAL_SUB_P521_TAC =
  ARM_MACRO_SIM_ABBREV_TAC p521_jdouble_mc 34 lvs
  `!(t:armstate) pcin pcout p3 n3 p1 n1 p2 n2.
    !m. read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) t = m
    ==>
    !n. read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) t = n
    ==>
    aligned 16 (read SP t) /\
    nonoverlapping (word pc,0x4444) (word_add (read p3 t) (word n3),72)
    ==> ensures arm
         (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
              read PC s = pcin /\
              read SP s = read SP t /\
              read X26 s = read X26 t /\
              read X27 s = read X27 t /\
              read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) s =
              m /\
              read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) s =
              n)
         (\s. read PC s = pcout /\
              (m < p_521 /\ n < p_521
               ==> &(read(memory :> bytes(word_add (read p3 t) (word n3),
                     8 * 9)) s) = (&m - &n) rem &p_521))
         (MAYCHANGE [PC; X3; X4; X5; X6; X7; X8; X9; X10; X11; X12; X13] ,,
          MAYCHANGE
               [memory :> bytes(word_add (read p3 t) (word n3),8 * 9)] ,,
          MAYCHANGE SOME_FLAGS)`
 (REWRITE_TAC[C_ARGUMENTS; C_RETURN; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN ASSUME_TAC) THEN

  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN
  FIRST_ASSUM(BIGNUM_DIGITIZE_TAC "n_" o lhand o concl) THEN
  FIRST_ASSUM(BIGNUM_DIGITIZE_TAC "m_" o lhand o concl) THEN

  (*** Initial subtraction x - y, comparison result ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC [3;4;7;8;11;12;15;16;19] (1--19) THEN

  SUBGOAL_THEN `carry_s19 <=> m < n` SUBST_ALL_TAC THENL
   [MATCH_MP_TAC FLAG_FROM_CARRY_LT THEN EXISTS_TAC `576` THEN
    MAP_EVERY EXPAND_TAC ["m"; "n"] THEN
    REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DECARRY_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN BOUNDER_TAC[];
    ALL_TAC] THEN

  (*** Further optional subtraction mod 2^521 ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (20--28) (20--34) THEN
  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN STRIP_TAC THEN

  (*** Map things into the reals, doing case analysis over comparison ***)

  TRANS_TAC EQ_TRANS `if m < n then &m - &n + &p_521:int else &m - &n` THEN
  CONJ_TAC THENL
   [ONCE_REWRITE_TAC[int_eq] THEN ONCE_REWRITE_TAC[COND_RAND] THEN
   REWRITE_TAC[int_of_num_th; int_sub_th; int_add_th];
   CONV_TAC SYM_CONV THEN MATCH_MP_TAC INT_REM_UNIQ THEN
   EXISTS_TAC `if m:num < n then --(&1):int else &0` THEN
   MAP_EVERY UNDISCH_TAC [`m < p_521`; `n < p_521`] THEN
   REWRITE_TAC[GSYM INT_OF_NUM_CLAUSES; p_521] THEN INT_ARITH_TAC] THEN

  (*** Hence show that we get the right result in 521 bits ***)

  CONV_TAC SYM_CONV THEN
  CONV_TAC(RAND_CONV(RAND_CONV BIGNUM_LEXPAND_CONV)) THEN
  ASM_REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
  MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
  MAP_EVERY EXISTS_TAC [`521`; `&0:real`] THEN CONJ_TAC THENL
   [MAP_EVERY UNDISCH_TAC [`m < p_521`; `n < p_521`] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; p_521] THEN REAL_ARITH_TAC;
    ALL_TAC] THEN
  CONJ_TAC THENL [BOUNDER_TAC[]; REWRITE_TAC[INTEGER_CLOSED]] THEN
  ABBREV_TAC `bb <=> m:num < n` THEN MAP_EVERY EXPAND_TAC ["m"; "n"] THEN
  REWRITE_TAC[bignum_of_wordlist; VAL_WORD_AND_MASK_WORD] THEN
  REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; REAL_OF_NUM_MOD; p_521] THEN
  ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
  COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC);;

(* ------------------------------------------------------------------------- *)
(* Instance (12,9) of cmsub (the only one used in this code).                *)
(* ------------------------------------------------------------------------- *)

let LOCAL_CMSUBC9_P521_TAC =
  ARM_MACRO_SIM_ABBREV_TAC p521_jdouble_mc 107 lvs
  `!(t:armstate) pcin pcout p3 n3 p1 n1 p2 n2.
    !m. read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) t = m
    ==>
    !n. read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) t = n
    ==>
    aligned 16 (read SP t) /\
    nonoverlapping (word pc,0x4444) (word_add (read p3 t) (word n3),72) /\
    nonoverlapping (read X26 t,216) (stackpointer,512) /\
    nonoverlapping (read X27 t,216) (stackpointer,512)
    ==> ensures arm
         (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
              read PC s = pcin /\
              read SP s = read SP t /\
              read X26 s = read X26 t /\
              read X27 s = read X27 t /\
              read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) s =
              m /\
              read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) s =
              n)
             (\s. read PC s = pcout /\
                  (m < 2 * p_521 /\ n <= p_521
                   ==> &(read(memory :> bytes(word_add (read p3 t) (word n3),
                            8 * 9)) s) = (&12 * &m - &9 * &n) rem &p_521))
            (MAYCHANGE [PC; X0; X1; X2; X3; X4; X5; X6; X7; X8; X9;
                        X10; X11; X12; X13; X14; X15; X16; X17;
                        X19; X20; X21; X22; X23] ,,
             MAYCHANGE
               [memory :> bytes(word_add (read p3 t) (word n3),8 * 9)] ,,
             MAYCHANGE SOME_FLAGS)`
 (REWRITE_TAC[C_ARGUMENTS; C_RETURN; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN ASSUME_TAC) THEN

  (*** Globalize the bound assumption for simplicity ***)

  ASM_CASES_TAC `m < 2 * p_521 /\ n <= p_521` THENL
   [ASM_REWRITE_TAC[] THEN FIRST_X_ASSUM(CONJUNCTS_THEN ASSUME_TAC);
    ARM_SIM_TAC P521_JDOUBLE_EXEC (1--107)] THEN

  (*** Digitize and introduce the sign-flipped version of n ***)

  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "n_" o lhand o concl) THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "m_" o lhand o concl) THEN
  ABBREV_TAC
   `n' = bignum_of_wordlist
    [word_not n_0; word_not n_1; word_not n_2; word_not n_3; word_not n_4;
     word_not n_5; word_not n_6; word_not n_7; word_xor n_8 (word 0x1FF)]` THEN

  SUBGOAL_THEN `p_521 - n = n'` ASSUME_TAC THENL
   [MATCH_MP_TAC(ARITH_RULE `n + m:num = p ==> p - n = m`) THEN
    MAP_EVERY EXPAND_TAC ["n"; "n'"] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    SUBGOAL_THEN
     `&(val(word_xor (n_8:int64) (word 511))):real = &2 pow 9 - &1 - &(val n_8)`
    SUBST1_TAC THENL
     [REWRITE_TAC[REAL_VAL_WORD_XOR];
      REWRITE_TAC[REAL_VAL_WORD_NOT; DIMINDEX_64; p_521] THEN
      REAL_ARITH_TAC] THEN
    CONV_TAC WORD_REDUCE_CONV THEN CONV_TAC REAL_RAT_REDUCE_CONV THEN
    MATCH_MP_TAC(REAL_ARITH
     `n':real = n ==> (n + c) - &2 * n' = c - n`) THEN
    REWRITE_TAC[VAL_WORD_AND_MASK_WORD; ARITH_RULE `511 = 2 EXP 9 - 1`] THEN
    REWRITE_TAC[REAL_OF_NUM_EQ] THEN MATCH_MP_TAC MOD_LT THEN
    UNDISCH_TAC `n <= p_521` THEN
    DISCH_THEN(MP_TAC o MATCH_MP (ARITH_RULE
     `n <= p ==> n DIV 2 EXP 512 <= p DIV 2 EXP 512`)) THEN
    EXPAND_TAC "n" THEN
    CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `(&12 * &m - &9 * &n) rem &p_521 =
    (&12 * &m + &9 * (&p_521 - &n)) rem &p_521`
  SUBST1_TAC THENL
   [REWRITE_TAC[INT_REM_EQ] THEN CONV_TAC INTEGER_RULE;
    ASM_SIMP_TAC[INT_OF_NUM_CLAUSES; INT_OF_NUM_SUB; INT_OF_NUM_REM]] THEN

  (*** The basic multiply-add block = ca, then forget the components ***)

  ABBREV_TAC `ca = 12 * m + 9 * n'` THEN
  SUBGOAL_THEN `ca < 2 EXP 527` ASSUME_TAC THENL
   [MAP_EVERY EXPAND_TAC ["ca"; "n'"] THEN UNDISCH_TAC `m < 2 * p_521` THEN
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC] THEN

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (1--86) (1--86) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist
     [sum_s37; sum_s73; sum_s74; sum_s76;
      sum_s78; sum_s80; sum_s82; sum_s84; sum_s86] = ca`
  ASSUME_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN
    CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC] THEN
    EXPAND_TAC "ca" THEN CONJ_TAC THENL
     [UNDISCH_TAC `m < 2 * p_521` THEN EXPAND_TAC "n'" THEN
      REWRITE_TAC[REAL_OF_NUM_CLAUSES; LE_0; p_521] THEN ARITH_TAC;
      REWRITE_TAC[INTEGER_CLOSED]] THEN
    UNDISCH_THEN `p_521 - n = n'` (K ALL_TAC) THEN
    MAP_EVERY EXPAND_TAC ["m"; "n'"] THEN
    REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    REWRITE_TAC[REAL_VAL_WORD_NOT; DIMINDEX_64] THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `m:num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `n:num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `n':num` o concl)))] THEN

  (*** Breaking the problem down to (h + l) MOD p_521 ***)

  SUBGOAL_THEN `ca MOD p_521 = (ca DIV 2 EXP 521 + ca MOD 2 EXP 521) MOD p_521`
  SUBST1_TAC THENL
   [GEN_REWRITE_TAC (LAND_CONV o LAND_CONV)
     [ARITH_RULE `ca = 2 EXP 521 * ca DIV 2 EXP 521 + ca MOD 2 EXP 521`] THEN
    REWRITE_TAC[GSYM CONG] THEN MATCH_MP_TAC(NUMBER_RULE
     `(e == 1) (mod p) ==> (e * h + l == h + l) (mod p)`) THEN
    REWRITE_TAC[p_521; CONG] THEN ARITH_TAC;
    ALL_TAC] THEN
  SUBGOAL_THEN `ca DIV 2 EXP 521 < 2 EXP 64 /\ ca MOD 2 EXP 521 < 2 EXP 521`
  STRIP_ASSUME_TAC THENL
   [REWRITE_TAC[MOD_LT_EQ] THEN UNDISCH_TAC `ca < 2 EXP 527` THEN ARITH_TAC;
    ALL_TAC] THEN

  (*** Splitting up and stuffing 1 bits into the low part ***)

  ARM_STEPS_TAC P521_JDOUBLE_EXEC (87--89) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[GSYM WORD_AND_ASSOC; DIMINDEX_64;
      NUM_REDUCE_CONV `9 MOD 64`]) THEN
  MAP_EVERY ABBREV_TAC
   [`h:int64 = word_ushr sum_s86 9`;
    `d:int64 = word_or sum_s86 (word 18446744073709551104)`;
    `dd:int64 = word_and sum_s73 (word_and sum_s74 (word_and sum_s76
      (word_and sum_s78 (word_and sum_s80 (word_and sum_s82 sum_s84)))))`] THEN

  (*** The comparison in its direct condensed form ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (90--92) (90--92) THEN
  SUBGOAL_THEN
   `carry_s92 <=>
    2 EXP 192 <=
      2 EXP 128 * val(d:int64) + 2 EXP 64 * val(dd:int64) +
      val(h:int64) + val(sum_s37:int64) + 1`
  (ASSUME_TAC o SYM) THENL
   [MATCH_MP_TAC FLAG_FROM_CARRY_LE THEN EXISTS_TAC `192` THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DECARRY_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN BOUNDER_TAC[];
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Finish the simulation before completing the mathematics ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (93--101) (93--107) THEN
  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN
  CONV_TAC(LAND_CONV BIGNUM_LEXPAND_CONV) THEN ASM_REWRITE_TAC[] THEN
  DISCARD_STATE_TAC "s107" THEN

  (*** Evaluate d and un-condense the inequality ***)

  SUBGOAL_THEN
   `val(d:int64) = 2 EXP 9 * (2 EXP 55 - 1) + val(sum_s86:int64) MOD 2 EXP 9`
  SUBST_ALL_TAC THENL
   [EXPAND_TAC "d" THEN ONCE_REWRITE_TAC[WORD_BITWISE_RULE
     `word_or a b = word_or b (word_and a (word_not b))`] THEN
    SIMP_TAC[VAL_WORD_OR_DISJOINT; WORD_BITWISE_RULE
     `word_and x (word_and y (word_not x)) = word 0`] THEN
    REWRITE_TAC[GSYM VAL_WORD_AND_MASK_WORD] THEN
    CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC WORD_REDUCE_CONV;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 512 * val(sum_s86:int64) MOD 2 EXP 9 +
    bignum_of_wordlist
     [sum_s37; sum_s73; sum_s74; sum_s76; sum_s78; sum_s80; sum_s82; sum_s84] =
    ca MOD 2 EXP 521`
  (LABEL_TAC "*") THENL
   [CONV_TAC SYM_CONV THEN EXPAND_TAC "ca" THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    REWRITE_TAC[ARITH_RULE `2 EXP 521 = 2 EXP 512 * 2 EXP 9`] THEN
    REWRITE_TAC[SYM(NUM_REDUCE_CONV `64 * 8`)] THEN
    SIMP_TAC[LENGTH; ARITH_LT; ARITH_LE; MOD_MULT_MOD; ADD_CLAUSES;
             ARITH_SUC; BIGNUM_OF_WORDLIST_BOUND; MOD_LT; DIV_LT;
             MOD_MULT_ADD; DIV_MULT_ADD; EXP_EQ_0; ARITH_EQ] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN ARITH_TAC;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 521 <= ca MOD 2 EXP 521 + val(h:int64) + 1 <=> carry_s92`
  MP_TAC THENL
   [REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN EXPAND_TAC "carry_s92" THEN
    ONCE_REWRITE_TAC[bignum_of_wordlist] THEN
    MATCH_MP_TAC(TAUT
     `!p q. ((p ==> ~r) /\ (q ==> ~s)) /\ (p <=> q) /\ (~p /\ ~q ==> (r <=> s))
            ==> (r <=> s)`) THEN
    MAP_EVERY EXISTS_TAC
     [`bignum_of_wordlist
        [sum_s73; sum_s74; sum_s76; sum_s78; sum_s80; sum_s82; sum_s84] <
       2 EXP (64 * 7) - 1`;
      `val(dd:int64) < 2 EXP 64 - 1`] THEN
    CONJ_TAC THENL
     [CONJ_TAC THEN MATCH_MP_TAC(ARITH_RULE
      `2 EXP 64 * b + d < 2 EXP 64 * (a + 1) + c ==> a < b ==> ~(c <= d)`) THEN
      MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
      MP_TAC(SPEC `sum_s37:int64` VAL_BOUND_64) THEN ARITH_TAC;
      SIMP_TAC[BIGNUM_OF_WORDLIST_LT_MAX; LENGTH; ARITH_EQ; ARITH_SUC]] THEN
    REWRITE_TAC[GSYM NOT_ALL] THEN MP_TAC(ISPEC `dd:int64` VAL_EQ_MAX) THEN
    SIMP_TAC[VAL_BOUND_64; DIMINDEX_64; ARITH_RULE
      `a < n ==> (a < n - 1 <=> ~(a = n - 1))`] THEN
    DISCH_THEN SUBST1_TAC THEN EXPAND_TAC "dd" THEN
    REWRITE_TAC[WORD_NOT_AND; ALL; WORD_OR_EQ_0] THEN
    REWRITE_TAC[WORD_RULE `word_not d = e <=> d = word_not e`] THEN
    DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN SUBST1_TAC) THEN
    REWRITE_TAC[bignum_of_wordlist] THEN CONV_TAC WORD_REDUCE_CONV THEN
    MP_TAC(ARITH_RULE `val(sum_s86:int64) MOD 2 EXP 9 = 511 \/
                       val(sum_s86:int64) MOD 2 EXP 9 < 511`) THEN
    MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
    MP_TAC(SPEC `sum_s37:int64` VAL_BOUND_64) THEN ARITH_TAC;
    FIRST_X_ASSUM(K ALL_TAC o check (is_iff o concl))] THEN

  (*** Also evaluate h ***)

  SUBGOAL_THEN `val(h:int64) = ca DIV 2 EXP 521` SUBST_ALL_TAC THENL
   [EXPAND_TAC "h" THEN REWRITE_TAC[VAL_WORD_USHR] THEN
    EXPAND_TAC "ca" THEN
    CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    REWRITE_TAC[];
    ALL_TAC] THEN

  (*** Now complete the mathematics ***)

  SUBGOAL_THEN
   `2 EXP 521 <= ca MOD 2 EXP 521 + ca DIV 2 EXP 521 + 1 <=>
    p_521 <= ca DIV 2 EXP 521 + ca MOD 2 EXP 521`
  SUBST1_TAC THENL [REWRITE_TAC[p_521] THEN ARITH_TAC; DISCH_TAC] THEN
  CONV_TAC SYM_CONV THEN MATCH_MP_TAC EQUAL_FROM_CONGRUENT_MOD_MOD THEN
  MAP_EVERY EXISTS_TAC
   [`521`;
    `if ca DIV 2 EXP 521 + ca MOD 2 EXP 521 < p_521
     then &(ca DIV 2 EXP 521 + ca MOD 2 EXP 521)
     else &(ca DIV 2 EXP 521 + ca MOD 2 EXP 521) - &p_521`] THEN
  REPEAT CONJ_TAC THENL
   [BOUNDER_TAC[];
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC;
    W(MP_TAC o PART_MATCH (lhand o rand) MOD_CASES o rand o lhand o snd) THEN
    ANTS_TAC THENL
     [UNDISCH_TAC `ca < 2 EXP 527` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
      DISCH_THEN SUBST1_TAC] THEN
    ONCE_REWRITE_TAC[COND_RAND] THEN
    SIMP_TAC[GSYM NOT_LE; COND_SWAP; GSYM REAL_OF_NUM_SUB; COND_ID]] THEN
  ASM_REWRITE_TAC[GSYM NOT_LE; COND_SWAP] THEN
  REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN
  REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
  REWRITE_TAC[VAL_WORD_AND_MASK_WORD; bignum_of_wordlist] THEN
  ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
  REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; REAL_OF_NUM_MOD; p_521] THEN
  CONV_TAC NUM_REDUCE_CONV THEN
  COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC);;

(* ------------------------------------------------------------------------- *)
(* Instances of cmsub41 (there is only one).                                 *)
(* ------------------------------------------------------------------------- *)

let LOCAL_CMSUB41_P521_TAC =
  ARM_MACRO_SIM_ABBREV_TAC p521_jdouble_mc 57 lvs
  `!(t:armstate) pcin pcout p3 n3 p1 n1 p2 n2.
    !m. read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) t = m
    ==>
    !n. read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) t = n
    ==>
    aligned 16 (read SP t) /\
    nonoverlapping (word pc,0x4444) (word_add (read p3 t) (word n3),72) /\
    nonoverlapping (read X26 t,216) (stackpointer,512) /\
    nonoverlapping (read X27 t,216) (stackpointer,512)
    ==> ensures arm
         (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
              read PC s = pcin /\
              read SP s = read SP t /\
              read X26 s = read X26 t /\
              read X27 s = read X27 t /\
              read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) s =
              m /\
              read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) s =
              n)
             (\s. read PC s = pcout /\
                  (m < 2 * p_521 /\ n <= p_521
                   ==> &(read(memory :> bytes(word_add (read p3 t) (word n3),
                            8 * 9)) s) = (&4 * &m - &n) rem &p_521))
            (MAYCHANGE [PC; X0; X1; X2; X3; X4; X5; X6; X7; X8; X9;
                        X10; X11; X12; X13; X14; X15] ,,
             MAYCHANGE
               [memory :> bytes(word_add (read p3 t) (word n3),8 * 9)] ,,
             MAYCHANGE SOME_FLAGS)`
 (REWRITE_TAC[C_ARGUMENTS; C_RETURN; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN ASSUME_TAC) THEN

  (*** Globalize the bound assumption for simplicity ***)

  ASM_CASES_TAC `m < 2 * p_521 /\ n <= p_521` THENL
   [ASM_REWRITE_TAC[] THEN FIRST_X_ASSUM(CONJUNCTS_THEN ASSUME_TAC);
    ARM_SIM_TAC P521_JDOUBLE_EXEC (1--57)] THEN

  (*** Digitize and introduce the sign-flipped version of n ***)

  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "n_" o lhand o concl) THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "m_" o lhand o concl) THEN
  ABBREV_TAC
   `n' = bignum_of_wordlist
    [word_not n_0; word_not n_1; word_not n_2; word_not n_3; word_not n_4;
     word_not n_5; word_not n_6; word_not n_7; word_xor n_8 (word 0x1FF)]` THEN

  SUBGOAL_THEN `p_521 - n = n'` ASSUME_TAC THENL
   [MATCH_MP_TAC(ARITH_RULE `n + m:num = p ==> p - n = m`) THEN
    MAP_EVERY EXPAND_TAC ["n"; "n'"] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    SUBGOAL_THEN
     `&(val(word_xor (n_8:int64) (word 511))):real = &2 pow 9 - &1 - &(val n_8)`
    SUBST1_TAC THENL
     [REWRITE_TAC[REAL_VAL_WORD_XOR];
      REWRITE_TAC[REAL_VAL_WORD_NOT; DIMINDEX_64; p_521] THEN
      REAL_ARITH_TAC] THEN
    CONV_TAC WORD_REDUCE_CONV THEN CONV_TAC REAL_RAT_REDUCE_CONV THEN
    MATCH_MP_TAC(REAL_ARITH
     `n':real = n ==> (n + c) - &2 * n' = c - n`) THEN
    REWRITE_TAC[VAL_WORD_AND_MASK_WORD; ARITH_RULE `511 = 2 EXP 9 - 1`] THEN
    REWRITE_TAC[REAL_OF_NUM_EQ] THEN MATCH_MP_TAC MOD_LT THEN
    UNDISCH_TAC `n <= p_521` THEN
    DISCH_THEN(MP_TAC o MATCH_MP (ARITH_RULE
     `n <= p ==> n DIV 2 EXP 512 <= p DIV 2 EXP 512`)) THEN
    EXPAND_TAC "n" THEN
    CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC] THEN

  (*** Now introduce the shifted version of m ***)

  ABBREV_TAC
   `m' = bignum_of_wordlist
     [word_shl m_0 2;
      word_subword ((word_join:int64->int64->int128) m_1 m_0) (62,64);
      word_subword ((word_join:int64->int64->int128) m_2 m_1) (62,64);
      word_subword ((word_join:int64->int64->int128) m_3 m_2) (62,64);
      word_subword ((word_join:int64->int64->int128) m_4 m_3) (62,64);
      word_subword ((word_join:int64->int64->int128) m_5 m_4) (62,64);
      word_subword ((word_join:int64->int64->int128) m_6 m_5) (62,64);
      word_subword ((word_join:int64->int64->int128) m_7 m_6) (62,64);
      word_subword ((word_join:int64->int64->int128) m_8 m_7) (62,64)]` THEN
  SUBGOAL_THEN `4 * m = m'` ASSUME_TAC THENL
   [SUBGOAL_THEN `m DIV 2 EXP 512 < 2 EXP 62` MP_TAC THENL
     [UNDISCH_TAC `m < 2 * p_521` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
      EXPAND_TAC "m" THEN
      CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
      REWRITE_TAC[GSYM UPPER_BITS_ZERO]] THEN
    EXPAND_TAC "m'" THEN POP_ASSUM_LIST(K ALL_TAC) THEN
    DISCH_THEN(fun th -> MP_TAC(SPEC `62` th) THEN MP_TAC(SPEC `63` th)) THEN
    CONV_TAC NUM_REDUCE_CONV THEN DISCH_TAC THEN DISCH_TAC THEN
    REWRITE_TAC[bignum_of_wordlist; REAL_OF_NUM_CLAUSES] THEN
    REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
    REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
    REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
    REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR;
                BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC NUM_RING;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `(&4 * &m - &n) rem &p_521 =
    (&4 * &m + (&p_521 - &n)) rem &p_521`
  SUBST1_TAC THENL
   [REWRITE_TAC[INT_REM_EQ] THEN CONV_TAC INTEGER_RULE;
    ASM_SIMP_TAC[INT_OF_NUM_CLAUSES; INT_OF_NUM_SUB; INT_OF_NUM_REM]] THEN

  (*** The basic multiply-add block = ca, then forget the components ***)

  ABBREV_TAC `ca:num = m' + n'` THEN
  SUBGOAL_THEN `ca < 2 EXP 527` ASSUME_TAC THENL
   [MAP_EVERY EXPAND_TAC ["ca"; "m'"; "n'"] THEN
    UNDISCH_TAC `m < 2 * p_521` THEN
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC] THEN

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC [17;18;20;22;25;27;30;32;36] (1--36) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist
     [sum_s17; sum_s18; sum_s20; sum_s22;
      sum_s25; sum_s27; sum_s30; sum_s32; sum_s36] = ca`
  ASSUME_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN
    CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC] THEN CONJ_TAC THENL
     [UNDISCH_TAC `ca < 2 EXP 527` THEN REWRITE_TAC[REAL_OF_NUM_CLAUSES] THEN
      ARITH_TAC;
      REWRITE_TAC[INTEGER_CLOSED] THEN EXPAND_TAC "ca"] THEN
    UNDISCH_THEN `p_521 - n = n'` (K ALL_TAC) THEN
    UNDISCH_THEN `4 * m = m'` (K ALL_TAC) THEN
    MAP_EVERY EXPAND_TAC ["m'"; "n'"] THEN
    REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    RULE_ASSUM_TAC(REWRITE_RULE[REAL_BITVAL_NOT]) THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    REWRITE_TAC[REAL_VAL_WORD_NOT; DIMINDEX_64] THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `m:num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `n:num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `n':num` o concl)))] THEN

  (*** Breaking the problem down to (h + l) MOD p_521 ***)

  SUBGOAL_THEN `ca MOD p_521 = (ca DIV 2 EXP 521 + ca MOD 2 EXP 521) MOD p_521`
  SUBST1_TAC THENL
   [GEN_REWRITE_TAC (LAND_CONV o LAND_CONV)
     [ARITH_RULE `ca = 2 EXP 521 * ca DIV 2 EXP 521 + ca MOD 2 EXP 521`] THEN
    REWRITE_TAC[GSYM CONG] THEN MATCH_MP_TAC(NUMBER_RULE
     `(e == 1) (mod p) ==> (e * h + l == h + l) (mod p)`) THEN
    REWRITE_TAC[p_521; CONG] THEN ARITH_TAC;
    ALL_TAC] THEN
  SUBGOAL_THEN `ca DIV 2 EXP 521 < 2 EXP 64 /\ ca MOD 2 EXP 521 < 2 EXP 521`
  STRIP_ASSUME_TAC THENL
   [REWRITE_TAC[MOD_LT_EQ] THEN UNDISCH_TAC `ca < 2 EXP 527` THEN ARITH_TAC;
    ALL_TAC] THEN

  (*** Splitting up and stuffing 1 bits into the low part ***)

  ARM_STEPS_TAC P521_JDOUBLE_EXEC (37--39) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[GSYM WORD_AND_ASSOC; DIMINDEX_64;
      NUM_REDUCE_CONV `9 MOD 64`]) THEN
  MAP_EVERY ABBREV_TAC
   [`h:int64 = word_ushr sum_s36 9`;
    `d:int64 = word_or sum_s36 (word 18446744073709551104)`;
    `dd:int64 = word_and sum_s18 (word_and sum_s20 (word_and sum_s22
      (word_and sum_s25 (word_and sum_s27 (word_and sum_s30 sum_s32)))))`] THEN

  (*** The comparison in its direct condensed form ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (40--42) (40--42) THEN
  SUBGOAL_THEN
   `carry_s42 <=>
    2 EXP 192 <=
      2 EXP 128 * val(d:int64) + 2 EXP 64 * val(dd:int64) +
      val(h:int64) + val(sum_s17:int64) + 1`
  (ASSUME_TAC o SYM) THENL
   [MATCH_MP_TAC FLAG_FROM_CARRY_LE THEN EXISTS_TAC `192` THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DECARRY_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN BOUNDER_TAC[];
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Finish the simulation before completing the mathematics ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (43--51) (43--57) THEN
  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN
  CONV_TAC(LAND_CONV BIGNUM_LEXPAND_CONV) THEN ASM_REWRITE_TAC[] THEN
  DISCARD_STATE_TAC "s57" THEN

  (*** Evaluate d and un-condense the inequality ***)

  SUBGOAL_THEN
   `val(d:int64) = 2 EXP 9 * (2 EXP 55 - 1) + val(sum_s36:int64) MOD 2 EXP 9`
  SUBST_ALL_TAC THENL
   [EXPAND_TAC "d" THEN ONCE_REWRITE_TAC[WORD_BITWISE_RULE
     `word_or a b = word_or b (word_and a (word_not b))`] THEN
    SIMP_TAC[VAL_WORD_OR_DISJOINT; WORD_BITWISE_RULE
     `word_and x (word_and y (word_not x)) = word 0`] THEN
    REWRITE_TAC[GSYM VAL_WORD_AND_MASK_WORD] THEN
    CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC WORD_REDUCE_CONV;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 512 * val(sum_s36:int64) MOD 2 EXP 9 +
    bignum_of_wordlist
     [sum_s17; sum_s18; sum_s20; sum_s22; sum_s25; sum_s27; sum_s30; sum_s32] =
    ca MOD 2 EXP 521`
  (LABEL_TAC "*") THENL
   [CONV_TAC SYM_CONV THEN EXPAND_TAC "ca" THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    REWRITE_TAC[ARITH_RULE `2 EXP 521 = 2 EXP 512 * 2 EXP 9`] THEN
    REWRITE_TAC[SYM(NUM_REDUCE_CONV `64 * 8`)] THEN
    SIMP_TAC[LENGTH; ARITH_LT; ARITH_LE; MOD_MULT_MOD; ADD_CLAUSES;
             ARITH_SUC; BIGNUM_OF_WORDLIST_BOUND; MOD_LT; DIV_LT;
             MOD_MULT_ADD; DIV_MULT_ADD; EXP_EQ_0; ARITH_EQ] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN ARITH_TAC;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 521 <= ca MOD 2 EXP 521 + val(h:int64) + 1 <=> carry_s42`
  MP_TAC THENL
   [REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN EXPAND_TAC "carry_s42" THEN
    ONCE_REWRITE_TAC[bignum_of_wordlist] THEN
    MATCH_MP_TAC(TAUT
     `!p q. ((p ==> ~r) /\ (q ==> ~s)) /\ (p <=> q) /\ (~p /\ ~q ==> (r <=> s))
            ==> (r <=> s)`) THEN
    MAP_EVERY EXISTS_TAC
     [`bignum_of_wordlist
        [sum_s18; sum_s20; sum_s22; sum_s25; sum_s27; sum_s30; sum_s32] <
       2 EXP (64 * 7) - 1`;
      `val(dd:int64) < 2 EXP 64 - 1`] THEN
    CONJ_TAC THENL
     [CONJ_TAC THEN MATCH_MP_TAC(ARITH_RULE
      `2 EXP 64 * b + d < 2 EXP 64 * (a + 1) + c ==> a < b ==> ~(c <= d)`) THEN
      MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
      MP_TAC(SPEC `sum_s17:int64` VAL_BOUND_64) THEN ARITH_TAC;
      SIMP_TAC[BIGNUM_OF_WORDLIST_LT_MAX; LENGTH; ARITH_EQ; ARITH_SUC]] THEN
    REWRITE_TAC[GSYM NOT_ALL] THEN MP_TAC(ISPEC `dd:int64` VAL_EQ_MAX) THEN
    SIMP_TAC[VAL_BOUND_64; DIMINDEX_64; ARITH_RULE
      `a < n ==> (a < n - 1 <=> ~(a = n - 1))`] THEN
    DISCH_THEN SUBST1_TAC THEN EXPAND_TAC "dd" THEN
    REWRITE_TAC[WORD_NOT_AND; ALL; WORD_OR_EQ_0] THEN
    REWRITE_TAC[WORD_RULE `word_not d = e <=> d = word_not e`] THEN
    DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN SUBST1_TAC) THEN
    REWRITE_TAC[bignum_of_wordlist] THEN CONV_TAC WORD_REDUCE_CONV THEN
    MP_TAC(ARITH_RULE `val(sum_s36:int64) MOD 2 EXP 9 = 511 \/
                       val(sum_s36:int64) MOD 2 EXP 9 < 511`) THEN
    MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
    MP_TAC(SPEC `sum_s17:int64` VAL_BOUND_64) THEN ARITH_TAC;
    FIRST_X_ASSUM(K ALL_TAC o check (is_iff o concl))] THEN

  (*** Also evaluate h ***)

  SUBGOAL_THEN `val(h:int64) = ca DIV 2 EXP 521` SUBST_ALL_TAC THENL
   [EXPAND_TAC "h" THEN REWRITE_TAC[VAL_WORD_USHR] THEN
    EXPAND_TAC "ca" THEN
    CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    REWRITE_TAC[];
    ALL_TAC] THEN

  (*** Now complete the mathematics ***)

  SUBGOAL_THEN
   `2 EXP 521 <= ca MOD 2 EXP 521 + ca DIV 2 EXP 521 + 1 <=>
    p_521 <= ca DIV 2 EXP 521 + ca MOD 2 EXP 521`
  SUBST1_TAC THENL [REWRITE_TAC[p_521] THEN ARITH_TAC; DISCH_TAC] THEN
  CONV_TAC SYM_CONV THEN MATCH_MP_TAC EQUAL_FROM_CONGRUENT_MOD_MOD THEN
  MAP_EVERY EXISTS_TAC
   [`521`;
    `if ca DIV 2 EXP 521 + ca MOD 2 EXP 521 < p_521
     then &(ca DIV 2 EXP 521 + ca MOD 2 EXP 521)
     else &(ca DIV 2 EXP 521 + ca MOD 2 EXP 521) - &p_521`] THEN
  REPEAT CONJ_TAC THENL
   [BOUNDER_TAC[];
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC;
    W(MP_TAC o PART_MATCH (lhand o rand) MOD_CASES o rand o lhand o snd) THEN
    ANTS_TAC THENL
     [UNDISCH_TAC `ca < 2 EXP 527` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
      DISCH_THEN SUBST1_TAC] THEN
    ONCE_REWRITE_TAC[COND_RAND] THEN
    SIMP_TAC[GSYM NOT_LE; COND_SWAP; GSYM REAL_OF_NUM_SUB; COND_ID]] THEN
  ASM_REWRITE_TAC[GSYM NOT_LE; COND_SWAP] THEN
  REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN
  REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
  REWRITE_TAC[VAL_WORD_AND_MASK_WORD; bignum_of_wordlist] THEN
  ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
  REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; REAL_OF_NUM_MOD; p_521] THEN
  CONV_TAC NUM_REDUCE_CONV THEN
  COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC);;

(* ------------------------------------------------------------------------- *)
(* Instances cmsub38 (there is only one).                                    *)
(* ------------------------------------------------------------------------- *)

let LOCAL_CMSUB38_P521_TAC =
  ARM_MACRO_SIM_ABBREV_TAC p521_jdouble_mc 82 lvs
  `!(t:armstate) pcin pcout p3 n3 p1 n1 p2 n2.
    !m. read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) t = m
    ==>
    !n. read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) t = n
    ==>
    aligned 16 (read SP t) /\
    nonoverlapping (word pc,0x4444) (word_add (read p3 t) (word n3),72) /\
    nonoverlapping (read X26 t,216) (stackpointer,512) /\
    nonoverlapping (read X27 t,216) (stackpointer,512)
    ==> ensures arm
         (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
              read PC s = pcin /\
              read SP s = read SP t /\
              read X26 s = read X26 t /\
              read X27 s = read X27 t /\
              read(memory :> bytes(word_add (read p1 t) (word n1),8 * 9)) s =
              m /\
              read(memory :> bytes(word_add (read p2 t) (word n2),8 * 9)) s =
              n)
             (\s. read PC s = pcout /\
                  (m < 2 * p_521 /\ n <= p_521
                   ==> &(read(memory :> bytes(word_add (read p3 t) (word n3),
                            8 * 9)) s) = (&3 * &m - &8 *  &n) rem &p_521))
            (MAYCHANGE [PC; X0; X1; X2; X3; X4; X5; X6; X7; X8; X9;
                        X10; X11; X12; X13; X14; X15; X16; X17;
                        X19; X20; X21; X22; X23] ,,
             MAYCHANGE
               [memory :> bytes(word_add (read p3 t) (word n3),8 * 9)] ,,
             MAYCHANGE SOME_FLAGS)`
 (REWRITE_TAC[C_ARGUMENTS; C_RETURN; SOME_FLAGS; NONOVERLAPPING_CLAUSES] THEN
  DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN ASSUME_TAC) THEN

  (*** Globalize the bound assumption for simplicity ***)

  ASM_CASES_TAC `m < 2 * p_521 /\ n <= p_521` THENL
   [ASM_REWRITE_TAC[] THEN FIRST_X_ASSUM(CONJUNCTS_THEN ASSUME_TAC);
    ARM_SIM_TAC P521_JDOUBLE_EXEC (1--82)] THEN

  (*** Digitize and introduce the shifted and flipped version of n ***)

  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "n_" o lhand o concl) THEN
  FIRST_ASSUM(BIGNUM_LDIGITIZE_TAC "m_" o lhand o concl) THEN
  ABBREV_TAC
   `n' = bignum_of_wordlist
     [word_shl (word_not n_0) 3;
      word_subword ((word_join:int64->int64->int128)
                    (word_not n_1) (word_not n_0)) (61,64);
      word_subword ((word_join:int64->int64->int128)
                    (word_not n_2) (word_not n_1)) (61,64);
      word_subword ((word_join:int64->int64->int128)
                    (word_not n_3) (word_not n_2)) (61,64);
      word_subword ((word_join:int64->int64->int128)
                    (word_not n_4) (word_not n_3)) (61,64);
      word_subword ((word_join:int64->int64->int128)
                    (word_not n_5) (word_not n_4)) (61,64);
      word_subword ((word_join:int64->int64->int128)
                    (word_not n_6) (word_not n_5)) (61,64);
      word_subword ((word_join:int64->int64->int128)
                    (word_not n_7) (word_not n_6)) (61,64);
      word_subword ((word_join:int64->int64->int128)
                    (word_xor n_8 (word 0x1FF)) (word_not n_7)) (61,64)]` THEN
  SUBGOAL_THEN `8 * (p_521 - n) = n'` ASSUME_TAC THENL
   [MATCH_MP_TAC(ARITH_RULE `8 * n + m = 8 * p ==> 8 * (p - n) = m`) THEN
    SUBGOAL_THEN `n DIV 2 EXP 512 < 2 EXP 9` MP_TAC THENL
     [UNDISCH_TAC `n <= p_521` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
      EXPAND_TAC "n" THEN
      CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
      REWRITE_TAC[GSYM UPPER_BITS_ZERO]] THEN
    EXPAND_TAC "n'" THEN POP_ASSUM_LIST(K ALL_TAC) THEN
    DISCH_THEN(MP_TAC o MATCH_MP (MESON[]
     `(!i. P i) ==> (!i. i < 64 ==> P i)`)) THEN
    CONV_TAC(LAND_CONV EXPAND_CASES_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN STRIP_TAC THEN
    REWRITE_TAC[bignum_of_wordlist; REAL_OF_NUM_CLAUSES] THEN
    REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
    REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
    REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
    REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_SHL;
                BIT_WORD_NOT; BIT_WORD_XOR; DIMINDEX_64; DIMINDEX_128] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; REAL_BITVAL_NOT] THEN
    REWRITE_TAC[p_521] THEN CONV_TAC REAL_RING;
    ALL_TAC] THEN

  (*** Now introduce the shifted version of m for 3 * m = 2 * m + m ***)

  ABBREV_TAC
   `m' = bignum_of_wordlist
     [word_shl m_0 1;
      word_subword ((word_join:int64->int64->int128) m_1 m_0) (63,64);
      word_subword ((word_join:int64->int64->int128) m_2 m_1) (63,64);
      word_subword ((word_join:int64->int64->int128) m_3 m_2) (63,64);
      word_subword ((word_join:int64->int64->int128) m_4 m_3) (63,64);
      word_subword ((word_join:int64->int64->int128) m_5 m_4) (63,64);
      word_subword ((word_join:int64->int64->int128) m_6 m_5) (63,64);
      word_subword ((word_join:int64->int64->int128) m_7 m_6) (63,64);
      word_subword ((word_join:int64->int64->int128) m_8 m_7) (63,64)]` THEN
  SUBGOAL_THEN `2 * m = m'` ASSUME_TAC THENL
   [SUBGOAL_THEN `m DIV 2 EXP 512 < 2 EXP 63` MP_TAC THENL
     [UNDISCH_TAC `m < 2 * p_521` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
      EXPAND_TAC "m" THEN
      CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
      REWRITE_TAC[GSYM UPPER_BITS_ZERO]] THEN
    EXPAND_TAC "m'" THEN POP_ASSUM_LIST(K ALL_TAC) THEN
    DISCH_THEN(MP_TAC o SPEC `63`) THEN
    CONV_TAC NUM_REDUCE_CONV THEN DISCH_TAC THEN
    REWRITE_TAC[bignum_of_wordlist; REAL_OF_NUM_CLAUSES] THEN
    REWRITE_TAC[val_def; DIMINDEX_64; bignum_of_wordlist] THEN
    REWRITE_TAC[ARITH_RULE `i < 64 <=> 0 <= i /\ i <= 63`] THEN
    REWRITE_TAC[GSYM IN_NUMSEG; IN_GSPEC] THEN
    REWRITE_TAC[BIT_WORD_SUBWORD; BIT_WORD_JOIN; BIT_WORD_USHR;
                BIT_WORD_SHL; DIMINDEX_64; DIMINDEX_128] THEN
    CONV_TAC NUM_REDUCE_CONV THEN
    CONV_TAC(ONCE_DEPTH_CONV EXPAND_NSUM_CONV) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC WORD_REDUCE_CONV THEN REWRITE_TAC[BITVAL_CLAUSES] THEN
    CONV_TAC NUM_RING;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `(&3 * &m - &8 *  &n) rem &p_521 =
    (&2 * &m + &m + &8 *  (&p_521 - &n)) rem &p_521`
  SUBST1_TAC THENL
   [REWRITE_TAC[INT_REM_EQ] THEN CONV_TAC INTEGER_RULE;
    ASM_SIMP_TAC[INT_OF_NUM_CLAUSES; INT_OF_NUM_SUB; INT_OF_NUM_REM]] THEN

  (*** The basic multiply-add block = ca, then forget the components ***)

  ABBREV_TAC `ca = m' + m + n'` THEN
  SUBGOAL_THEN `ca < 2 EXP 527` ASSUME_TAC THENL
   [MAP_EVERY EXPAND_TAC ["ca"; "m'"; "n'"] THEN
    UNDISCH_TAC `m < 2 * p_521` THEN
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC] THEN

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC
   [3;5;8;10;13;15;18;20;23;27;30;34;38;43;47;52;56;61] (1--61) THEN
  SUBGOAL_THEN
   `bignum_of_wordlist
     [sum_s27; sum_s30; sum_s34; sum_s38;
      sum_s43; sum_s47; sum_s52; sum_s56; sum_s61] = ca`
  ASSUME_TAC THENL
   [REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; bignum_of_wordlist] THEN
    MATCH_MP_TAC EQUAL_FROM_CONGRUENT_REAL THEN
    MAP_EVERY EXISTS_TAC [`576`; `&0:real`] THEN
    CONJ_TAC THENL [BOUNDER_TAC[]; ALL_TAC] THEN CONJ_TAC THENL
     [UNDISCH_TAC `ca < 2 EXP 527` THEN REWRITE_TAC[REAL_OF_NUM_CLAUSES] THEN
      ARITH_TAC;
      REWRITE_TAC[INTEGER_CLOSED] THEN EXPAND_TAC "ca"] THEN
    UNDISCH_THEN `8 * (p_521 - n) = n'` (K ALL_TAC) THEN
    UNDISCH_THEN `2 * m = m'` (K ALL_TAC) THEN
    MAP_EVERY EXPAND_TAC ["m"; "m'"; "n'"] THEN
    REWRITE_TAC[bignum_of_wordlist; GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
    REWRITE_TAC[REAL_VAL_WORD_NOT; DIMINDEX_64] THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC;
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `m:num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `n:num` o concl))) THEN
    REPEAT(FIRST_X_ASSUM(K ALL_TAC o check (vfree_in `n':num` o concl)))] THEN

  (*** Breaking the problem down to (h + l) MOD p_521 ***)

  SUBGOAL_THEN `ca MOD p_521 = (ca DIV 2 EXP 521 + ca MOD 2 EXP 521) MOD p_521`
  SUBST1_TAC THENL
   [GEN_REWRITE_TAC (LAND_CONV o LAND_CONV)
     [ARITH_RULE `ca = 2 EXP 521 * ca DIV 2 EXP 521 + ca MOD 2 EXP 521`] THEN
    REWRITE_TAC[GSYM CONG] THEN MATCH_MP_TAC(NUMBER_RULE
     `(e == 1) (mod p) ==> (e * h + l == h + l) (mod p)`) THEN
    REWRITE_TAC[p_521; CONG] THEN ARITH_TAC;
    ALL_TAC] THEN
  SUBGOAL_THEN `ca DIV 2 EXP 521 < 2 EXP 64 /\ ca MOD 2 EXP 521 < 2 EXP 521`
  STRIP_ASSUME_TAC THENL
   [REWRITE_TAC[MOD_LT_EQ] THEN UNDISCH_TAC `ca < 2 EXP 527` THEN ARITH_TAC;
    ALL_TAC] THEN

  (*** Splitting up and stuffing 1 bits into the low part ***)

  ARM_STEPS_TAC P521_JDOUBLE_EXEC (62--64) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[GSYM WORD_AND_ASSOC; DIMINDEX_64;
      NUM_REDUCE_CONV `9 MOD 64`]) THEN
  MAP_EVERY ABBREV_TAC
   [`h:int64 = word_ushr sum_s61 9`;
    `d:int64 = word_or sum_s61 (word 18446744073709551104)`;
    `dd:int64 = word_and sum_s30 (word_and sum_s34 (word_and sum_s38
      (word_and sum_s43 (word_and sum_s47 (word_and sum_s52 sum_s56)))))`] THEN

  (*** The comparison in its direct condensed form ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (65--67) (65--67) THEN
  SUBGOAL_THEN
   `carry_s67 <=>
    2 EXP 192 <=
      2 EXP 128 * val(d:int64) + 2 EXP 64 * val(dd:int64) +
      val(h:int64) + val(sum_s27:int64) + 1`
  (ASSUME_TAC o SYM) THENL
   [MATCH_MP_TAC FLAG_FROM_CARRY_LE THEN EXISTS_TAC `192` THEN
    REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES] THEN
    ACCUMULATOR_ASSUM_LIST(MP_TAC o end_itlist CONJ o DECARRY_RULE') THEN
    DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN BOUNDER_TAC[];
    ACCUMULATOR_POP_ASSUM_LIST(K ALL_TAC)] THEN

  (*** Finish the simulation before completing the mathematics ***)

  ARM_ACCSTEPS_TAC P521_JDOUBLE_EXEC (68--76) (68--82) THEN
  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN
  CONV_TAC(LAND_CONV BIGNUM_LEXPAND_CONV) THEN ASM_REWRITE_TAC[] THEN
  DISCARD_STATE_TAC "s82" THEN

  (*** Evaluate d and un-condense the inequality ***)

  SUBGOAL_THEN
   `val(d:int64) = 2 EXP 9 * (2 EXP 55 - 1) + val(sum_s61:int64) MOD 2 EXP 9`
  SUBST_ALL_TAC THENL
   [EXPAND_TAC "d" THEN ONCE_REWRITE_TAC[WORD_BITWISE_RULE
     `word_or a b = word_or b (word_and a (word_not b))`] THEN
    SIMP_TAC[VAL_WORD_OR_DISJOINT; WORD_BITWISE_RULE
     `word_and x (word_and y (word_not x)) = word 0`] THEN
    REWRITE_TAC[GSYM VAL_WORD_AND_MASK_WORD] THEN
    CONV_TAC NUM_REDUCE_CONV THEN CONV_TAC WORD_REDUCE_CONV;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 512 * val(sum_s61:int64) MOD 2 EXP 9 +
    bignum_of_wordlist
     [sum_s27; sum_s30; sum_s34; sum_s38; sum_s43; sum_s47; sum_s52; sum_s56] =
    ca MOD 2 EXP 521`
  (LABEL_TAC "*") THENL
   [CONV_TAC SYM_CONV THEN EXPAND_TAC "ca" THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SPLIT_RULE(8,1)] THEN
    REWRITE_TAC[ARITH_RULE `2 EXP 521 = 2 EXP 512 * 2 EXP 9`] THEN
    REWRITE_TAC[SYM(NUM_REDUCE_CONV `64 * 8`)] THEN
    SIMP_TAC[LENGTH; ARITH_LT; ARITH_LE; MOD_MULT_MOD; ADD_CLAUSES;
             ARITH_SUC; BIGNUM_OF_WORDLIST_BOUND; MOD_LT; DIV_LT;
             MOD_MULT_ADD; DIV_MULT_ADD; EXP_EQ_0; ARITH_EQ] THEN
    REWRITE_TAC[BIGNUM_OF_WORDLIST_SING] THEN ARITH_TAC;
    ALL_TAC] THEN

  SUBGOAL_THEN
   `2 EXP 521 <= ca MOD 2 EXP 521 + val(h:int64) + 1 <=> carry_s67`
  MP_TAC THENL
   [REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN EXPAND_TAC "carry_s67" THEN
    ONCE_REWRITE_TAC[bignum_of_wordlist] THEN
    MATCH_MP_TAC(TAUT
     `!p q. ((p ==> ~r) /\ (q ==> ~s)) /\ (p <=> q) /\ (~p /\ ~q ==> (r <=> s))
            ==> (r <=> s)`) THEN
    MAP_EVERY EXISTS_TAC
     [`bignum_of_wordlist
        [sum_s30; sum_s34; sum_s38; sum_s43; sum_s47; sum_s52; sum_s56] <
       2 EXP (64 * 7) - 1`;
      `val(dd:int64) < 2 EXP 64 - 1`] THEN
    CONJ_TAC THENL
     [CONJ_TAC THEN MATCH_MP_TAC(ARITH_RULE
      `2 EXP 64 * b + d < 2 EXP 64 * (a + 1) + c ==> a < b ==> ~(c <= d)`) THEN
      MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
      MP_TAC(SPEC `sum_s27:int64` VAL_BOUND_64) THEN ARITH_TAC;
      SIMP_TAC[BIGNUM_OF_WORDLIST_LT_MAX; LENGTH; ARITH_EQ; ARITH_SUC]] THEN
    REWRITE_TAC[GSYM NOT_ALL] THEN MP_TAC(ISPEC `dd:int64` VAL_EQ_MAX) THEN
    SIMP_TAC[VAL_BOUND_64; DIMINDEX_64; ARITH_RULE
      `a < n ==> (a < n - 1 <=> ~(a = n - 1))`] THEN
    DISCH_THEN SUBST1_TAC THEN EXPAND_TAC "dd" THEN
    REWRITE_TAC[WORD_NOT_AND; ALL; WORD_OR_EQ_0] THEN
    REWRITE_TAC[WORD_RULE `word_not d = e <=> d = word_not e`] THEN
    DISCH_THEN(REPEAT_TCL CONJUNCTS_THEN SUBST1_TAC) THEN
    REWRITE_TAC[bignum_of_wordlist] THEN CONV_TAC WORD_REDUCE_CONV THEN
    MP_TAC(ARITH_RULE `val(sum_s61:int64) MOD 2 EXP 9 = 511 \/
                       val(sum_s61:int64) MOD 2 EXP 9 < 511`) THEN
    MP_TAC(SPEC `h:int64` VAL_BOUND_64) THEN
    MP_TAC(SPEC `sum_s27:int64` VAL_BOUND_64) THEN ARITH_TAC;
    FIRST_X_ASSUM(K ALL_TAC o check (is_iff o concl))] THEN

  (*** Also evaluate h ***)

  SUBGOAL_THEN `val(h:int64) = ca DIV 2 EXP 521` SUBST_ALL_TAC THENL
   [EXPAND_TAC "h" THEN REWRITE_TAC[VAL_WORD_USHR] THEN
    EXPAND_TAC "ca" THEN
    CONV_TAC(ONCE_DEPTH_CONV BIGNUM_OF_WORDLIST_DIV_CONV) THEN
    REWRITE_TAC[];
    ALL_TAC] THEN

  (*** Now complete the mathematics ***)

  SUBGOAL_THEN
   `2 EXP 521 <= ca MOD 2 EXP 521 + ca DIV 2 EXP 521 + 1 <=>
    p_521 <= ca DIV 2 EXP 521 + ca MOD 2 EXP 521`
  SUBST1_TAC THENL [REWRITE_TAC[p_521] THEN ARITH_TAC; DISCH_TAC] THEN
  CONV_TAC SYM_CONV THEN MATCH_MP_TAC EQUAL_FROM_CONGRUENT_MOD_MOD THEN
  MAP_EVERY EXISTS_TAC
   [`521`;
    `if ca DIV 2 EXP 521 + ca MOD 2 EXP 521 < p_521
     then &(ca DIV 2 EXP 521 + ca MOD 2 EXP 521)
     else &(ca DIV 2 EXP 521 + ca MOD 2 EXP 521) - &p_521`] THEN
  REPEAT CONJ_TAC THENL
   [BOUNDER_TAC[];
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    REWRITE_TAC[p_521] THEN ARITH_TAC;
    ALL_TAC;
    W(MP_TAC o PART_MATCH (lhand o rand) MOD_CASES o rand o lhand o snd) THEN
    ANTS_TAC THENL
     [UNDISCH_TAC `ca < 2 EXP 527` THEN REWRITE_TAC[p_521] THEN ARITH_TAC;
      DISCH_THEN SUBST1_TAC] THEN
    ONCE_REWRITE_TAC[COND_RAND] THEN
    SIMP_TAC[GSYM NOT_LE; COND_SWAP; GSYM REAL_OF_NUM_SUB; COND_ID]] THEN
  ASM_REWRITE_TAC[GSYM NOT_LE; COND_SWAP] THEN
  REMOVE_THEN "*" (SUBST1_TAC o SYM) THEN
  REWRITE_TAC[SYM(NUM_REDUCE_CONV `2 EXP 9 - 1`)] THEN
  REWRITE_TAC[VAL_WORD_AND_MASK_WORD; bignum_of_wordlist] THEN
  ACCUMULATOR_POP_ASSUM_LIST(MP_TAC o end_itlist CONJ o DESUM_RULE') THEN
  REWRITE_TAC[GSYM REAL_OF_NUM_CLAUSES; REAL_OF_NUM_MOD; p_521] THEN
  CONV_TAC NUM_REDUCE_CONV THEN
  COND_CASES_TAC THEN ASM_REWRITE_TAC[BITVAL_CLAUSES] THEN
  DISCH_THEN(fun th -> REWRITE_TAC[th]) THEN REAL_INTEGER_TAC);;

(* ------------------------------------------------------------------------- *)
(* Overall point operation proof.                                            *)
(* ------------------------------------------------------------------------- *)

let unilemma0 = prove
 (`x = a MOD p_521 ==> x < p_521 /\ &x = &a rem &p_521`,
  REWRITE_TAC[INT_OF_NUM_REM; p_521] THEN ARITH_TAC);;

let unilemma1 = prove
 (`&x = a rem &p_521 ==> x < p_521 /\ &x = a rem &p_521`,
  SIMP_TAC[GSYM INT_OF_NUM_LT; INT_LT_REM_EQ; p_521] THEN INT_ARITH_TAC);;

let weierstrass_of_jacobian_p521_double = prove
 (`!P1 P2 x1 y1 z1 x3 y3 z3.
        jacobian_double_unexceptional nistp521
         (x1 rem &p_521,y1 rem &p_521,z1 rem &p_521) =
        (x3 rem &p_521,y3 rem &p_521,z3 rem &p_521)
       ==> weierstrass_of_jacobian (integer_mod_ring p_521)
                (x1 rem &p_521,y1 rem &p_521,z1 rem &p_521) = P1
            ==> weierstrass_of_jacobian (integer_mod_ring p_521)
                  (x3 rem &p_521,y3 rem &p_521,z3 rem &p_521) =
                group_mul p521_group P1 P1`,
  REPEAT GEN_TAC THEN DISCH_THEN(SUBST1_TAC o SYM) THEN
  DISCH_THEN(SUBST1_TAC o SYM) THEN REWRITE_TAC[nistp521; P521_GROUP] THEN
  MATCH_MP_TAC WEIERSTRASS_OF_JACOBIAN_DOUBLE_UNEXCEPTIONAL THEN
  ASM_REWRITE_TAC[FIELD_INTEGER_MOD_RING; PRIME_P521] THEN
  ASM_REWRITE_TAC[jacobian_point; INTEGER_MOD_RING_CHAR;
                  INTEGER_MOD_RING_CLAUSES; IN_INTEGER_MOD_RING_CARRIER] THEN
  REWRITE_TAC[INT_REM_POS_EQ; INT_LT_REM_EQ; GSYM INT_OF_NUM_CLAUSES] THEN
  REWRITE_TAC[p_521; b_521] THEN CONV_TAC INT_REDUCE_CONV);;

let represents_p521 = new_definition
 `represents_p521 P (x,y,z) <=>
        x < p_521 /\ y < p_521 /\ z < p_521 /\
        weierstrass_of_jacobian (integer_mod_ring p_521)
         (tripled (modular_decode (256,p_521)) (x,y,z)) = P`;;

let P521_JDOUBLE_CORRECT = time prove
 (`!p3 p1 t1 pc stackpointer.
        aligned 16 stackpointer /\
        ALL (nonoverlapping (stackpointer,512))
            [(word pc,0x4444); (p1,216); (p3,216)] /\
        nonoverlapping (p3,216) (word pc,0x4444)
        ==> ensures arm
             (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
                  read PC s = word(pc + 0x18) /\
                  read SP s = stackpointer /\
                  C_ARGUMENTS [p3; p1] s /\
                  bignum_triple_from_memory (p1,9) s = t1)
             (\s. read PC s = word (pc + 0x4428) /\
                  !P. represents_p521 P t1
                      ==> represents_p521 (group_mul p521_group P P)
                            (bignum_triple_from_memory(p3,9) s))
          (MAYCHANGE [PC; X0; X1; X2; X3; X4; X5; X6; X7; X8; X9; X10;
                      X11; X12; X13; X14; X15; X16; X17; X19; X20;
                      X21; X22; X23; X24; X25; X26; X27] ,,
           MAYCHANGE SOME_FLAGS ,,
           MAYCHANGE [memory :> bytes(p3,216);
                      memory :> bytes(stackpointer,512)])`,
  REWRITE_TAC[FORALL_PAIR_THM] THEN
  MAP_EVERY X_GEN_TAC
   [`p3:int64`; `p1:int64`; `x:num`; `y:num`; `z:num`;
    `pc:num`; `stackpointer:int64`] THEN
  REWRITE_TAC[ALLPAIRS; ALL; NONOVERLAPPING_CLAUSES] THEN STRIP_TAC THEN
  REWRITE_TAC[C_ARGUMENTS; SOME_FLAGS; PAIR_EQ; bignum_triple_from_memory] THEN
  CONV_TAC(ONCE_DEPTH_CONV NUM_MULT_CONV) THEN
  CONV_TAC(ONCE_DEPTH_CONV NORMALIZE_RELATIVE_ADDRESS_CONV) THEN
  REWRITE_TAC[BIGNUM_FROM_MEMORY_BYTES] THEN ENSURES_INIT_TAC "s0" THEN

  LOCAL_SQR_P521_TAC 2 ["z2";"z_1"] THEN
  LOCAL_SQR_P521_TAC 0 ["y2";"y_1"] THEN
  LOCAL_ADD_P521_TAC 0 ["t1";"x_1";"z2"] THEN
  LOCAL_SUB_P521_TAC 0 ["t2";"x_1";"z2"] THEN
  LOCAL_MUL_P521_TAC 0 ["x2p";"t1";"t2"] THEN
  LOCAL_ADD_P521_TAC 0 ["t1";"y_1";"z_1"] THEN
  LOCAL_SQR_P521_TAC 0 ["x4p";"x2p"] THEN
  LOCAL_MUL_P521_TAC 0 ["xy2";"x_1";"y2"] THEN
  LOCAL_SQR_P521_TAC 0 ["t2";"t1"] THEN
  LOCAL_CMSUBC9_P521_TAC 0 ["d";"xy2";"x4p"] THEN
  LOCAL_SUB_P521_TAC 0 ["t1";"t2";"z2"] THEN
  LOCAL_SQR_P521_TAC 0 ["y4";"y2"] THEN
  LOCAL_SUB_P521_TAC 0 ["z_3";"t1";"y2"] THEN
  LOCAL_MUL_P521_TAC 0 ["dx2";"d";"x2p"] THEN
  LOCAL_CMSUB41_P521_TAC 0 ["x_3";"xy2";"d"] THEN
  LOCAL_CMSUB38_P521_TAC 0 ["y_3";"dx2";"y4"] THEN

  ENSURES_FINAL_STATE_TAC THEN ASM_REWRITE_TAC[] THEN
  DISCARD_STATE_TAC "s18" THEN
  DISCARD_MATCHING_ASSUMPTIONS [`nonoverlapping_modulo a b c`] THEN

  X_GEN_TAC `P:(int#int)option` THEN
  REWRITE_TAC[represents_p521; tripled] THEN
  REWRITE_TAC[modular_decode; INT_OF_NUM_CLAUSES; INT_OF_NUM_REM] THEN
  STRIP_TAC THEN
  REPEAT(FIRST_X_ASSUM(MP_TAC o check (is_imp o concl))) THEN
  REPEAT(ANTS_TAC THENL
   [REWRITE_TAC[p_521] THEN RULE_ASSUM_TAC(REWRITE_RULE[p_521]) THEN
    CONV_TAC NUM_REDUCE_CONV THEN ASM BOUNDER_TAC[];
    (DISCH_THEN(STRIP_ASSUME_TAC o MATCH_MP unilemma0) ORELSE
     DISCH_THEN(STRIP_ASSUME_TAC o MATCH_MP unilemma1) ORELSE
     STRIP_TAC)]) THEN
  REPEAT(CONJ_TAC THENL [FIRST_ASSUM ACCEPT_TAC; ALL_TAC]) THEN
  REPEAT(FIRST_X_ASSUM(K ALL_TAC o GEN_REWRITE_RULE I [GSYM NOT_LE])) THEN
  RULE_ASSUM_TAC(REWRITE_RULE
   [num_congruent; GSYM INT_OF_NUM_CLAUSES; GSYM INT_OF_NUM_REM]) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[GSYM INT_REM_EQ]) THEN
  RULE_ASSUM_TAC(ONCE_REWRITE_RULE[GSYM INT_SUB_REM; GSYM INT_ADD_REM]) THEN
  RULE_ASSUM_TAC(REWRITE_RULE[INT_POW_2]) THEN
  RULE_ASSUM_TAC(ONCE_REWRITE_RULE[GSYM INT_MUL_REM]) THEN
  REWRITE_TAC[GSYM INT_OF_NUM_REM; INT_REM_REM; GSYM INT_OF_NUM_CLAUSES] THEN
  FIRST_X_ASSUM(MP_TAC o
    check(can (term_match [] `weierstrass_of_jacobian f j = p`) o concl)) THEN
  MATCH_MP_TAC weierstrass_of_jacobian_p521_double THEN ASM_REWRITE_TAC[] THEN
  ASM_REWRITE_TAC[jacobian_double_unexceptional; nistp521;
                  INTEGER_MOD_RING_CLAUSES] THEN
  CONV_TAC(TOP_DEPTH_CONV let_CONV) THEN REWRITE_TAC[PAIR_EQ] THEN
  CONV_TAC INT_REM_DOWN_CONV THEN
  REPEAT CONJ_TAC THEN AP_THM_TAC THEN AP_TERM_TAC THEN INT_ARITH_TAC);;

let P521_JDOUBLE_SUBROUTINE_CORRECT = time prove
 (`!p3 p1 t1 pc stackpointer returnaddress.
        aligned 16 stackpointer /\
        ALL (nonoverlapping (word_sub stackpointer (word 592),592))
            [(word pc,0x4444); (p1,216); (p3,216)] /\
        nonoverlapping (p3,216) (word pc,0x4444)
        ==> ensures arm
             (\s. aligned_bytes_loaded s (word pc) p521_jdouble_mc /\
                  read PC s = word pc /\
                  read SP s = stackpointer /\
                  read X30 s = returnaddress /\
                  C_ARGUMENTS [p3; p1] s /\
                  bignum_triple_from_memory (p1,9) s = t1)
             (\s. read PC s = returnaddress /\
                  !P. represents_p521 P t1
                      ==> represents_p521 (group_mul p521_group P P)
                            (bignum_triple_from_memory(p3,9) s))
          (MAYCHANGE_REGS_AND_FLAGS_PERMITTED_BY_ABI ,,
           MAYCHANGE [memory :> bytes(p3,216);
                      memory :> bytes(word_sub stackpointer (word 592),592)])`,
  ARM_ADD_RETURN_STACK_TAC P521_JDOUBLE_EXEC
   P521_JDOUBLE_CORRECT
    `[X19; X20; X21; X22; X23; X24; X25; X26; X27; X28]`
   592);;
