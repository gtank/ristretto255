// Copyright (c) 2017 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!noasm

#include "textflag.h"


// Each quadword accumulator uses two registers
#define r00 R8
#define r01 R9
#define r10 R10
#define r11 R11
#define r20 R12
#define r21 R13
#define r30 R14
#define r31 R15
#define r40 BX
#define r41 CX

// func FeMulADX(zp *uint64, xp *uint64, yp *uint64)
TEXT ·FeMulADX(SB),NOSPLIT,$0
	MOVQ zp+0(FP), DI
	MOVQ xp+8(FP), SI
	MOVQ yp+16(FP), BP

	// Clear flags
	XORQ AX, AX

	// DX is the implicit second operand of MULX
	MOVQ 0(BP), DX // rdx <-- y0

	MULXQ 0(SI), R8, R9 // r0 <-- x0*y0

	MULXQ 8(SI), R10, R11 // r1 <-- x1*y0
	ADDQ R9, R10
	ADCQ $0, R11

	MULXQ 16(SI), R12, R13 // r2 <-- x2*y0
	ADDQ R11, R12
	ADCQ $0, R13

	MULXQ 24(SI), R14, R15 // r3 <-- x3*y0
	ADDQ R13, R14
	ADCQ $0, R15

	MULXQ 32(SI), BX, CX // r4 <-- x4*y0
	ADDQ R15, BX
	ADCQ $0, CX

	MOVQ R8, 0(DI)
	MOVQ R10, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)
	RET
