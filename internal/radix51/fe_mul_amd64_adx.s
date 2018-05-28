// Copyright (c) 2018 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!noasm

#include "textflag.h"

// func FeMulADX(zp *uint64, xp *uint64, yp *uint64)
TEXT ·FeMulADX(SB),NOSPLIT,$0
	MOVQ zp+0(FP), DI
	MOVQ xp+8(FP), SI
	MOVQ yp+16(FP), BP

	// The first diagonal sets up the accumulators.
	XORQ AX,AX

	MOVQ 0(BP), DX // rdx <-- y0
	MULXQ 0(SI), R8, R9 // r0 <-- x0*y0
	MOVQ R8, 0(DI)
	MULXQ 8(SI), R10, R11 // r1 <-- x1*y0
	ADDQ R9, R10
	MULXQ 16(SI), R12, R13 // r2 <-- x2*y0
	ADCQ R11, R12
	MULXQ 24(SI), R14, R15 // r3 <-- x3*y0
	ADCQ R13, R14
	MULXQ 32(SI), BX, CX // r4 <-- x4*y0
	ADCQ R15, BX

	// Consolidate carry chain into r5
	ADCQ AX, CX
	MOVQ CX, 40(DI)

	MOVQ R10, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)

	XORQ AX, AX // clear flags

	MOVQ 8(BP), DX // rdx <-- y1
	MULXQ 0(SI), R10, R11 // r1 <-- x0*y1
	ADOXQ 8(DI), R10
	MOVQ R10, 8(DI)
	MULXQ 8(SI), R12, R13 // r2 <-- x1*y1
	ADCXQ R11, R12
	ADOXQ 16(DI), R12
	MULXQ 16(SI), R14, R15 // r3 <-- x2*y1
	ADCXQ R13, R14
	ADOXQ 24(DI), R14
	MULXQ 24(SI), BX, CX // r4 <-- x3*y1
	ADCXQ R15, BX
	ADOXQ 32(DI), BX
	MULXQ 32(SI), R8, R9 // r5 <-- x4*y1
	ADCXQ CX, R8
	ADOXQ 40(DI), R8

	// Consolidate both carry chains into r6
	ADCXQ AX, R9
	ADOXQ AX, R9
	MOVQ R9, 48(DI)

	// Update accumulators
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)
	MOVQ R8, 40(DI)

	XORQ AX, AX // clear flags

	MOVQ 16(BP), DX // rdx <-- y2
	MULXQ 0(SI), R12, R13 // r2 <-- x0*y2
	ADOXQ 16(DI), R12
	MOVQ R12, 16(DI)
	MULXQ 8(SI), R14, R15 // r3 <-- x1*y2
	ADCXQ R13, R14
	ADOXQ 24(DI), R14
	MULXQ 16(SI), BX, CX // r4 <-- x2*y2
	ADCXQ R15, BX
	ADOXQ 32(DI), BX
	MULXQ 24(SI), R8, R9 // r5 <-- x3*y2
	ADCXQ CX, R8
	ADOXQ 40(DI), R8
	MULXQ 32(SI), R10, R11 // r6 <-- x4*y2
	ADCXQ R9, R10
	ADOXQ 48(DI), R10

	// Consolidate both carry chains into r7
	ADCXQ AX, R11
	ADOXQ AX, R11
	MOVQ R11, 56(DI)

	// Update accumulators
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)
	MOVQ R8, 40(DI)
	MOVQ R10, 48(DI)

	XORQ AX, AX // clear flags

	MOVQ 24(BP), DX // rdx <-- y3
	MULXQ 0(SI), R14, R15 // r3 <-- x0*y3
	ADOXQ 24(DI), R14
	MOVQ R14, 24(DI)
	MULXQ 8(SI), BX, CX // r4 <-- x1*y3
	ADCXQ R15, BX
	ADOXQ 32(DI), BX
	MULXQ 16(SI), R8, R9 // r5 <-- x2*y3
	ADCXQ CX, R8
	ADOXQ 40(DI), R8
	MULXQ 24(SI), R10, R11 // r6 <-- x3*y3
	ADCXQ R9, R10
	ADOXQ 48(DI), R10
	MULXQ 32(SI), R12, R13 //r7 <-- x4*y3
	ADCXQ R11, R12
	ADOXQ 56(DI), R12

	// Consolidate both carry chains into r8
	ADCXQ AX, R13
	ADOXQ AX, R13
	MOVQ R13, 64(DI)

	// Update accumulators
	MOVQ BX, 32(DI)
	MOVQ R8, 40(DI)
	MOVQ R10, 48(DI)
	MOVQ R12, 56(DI)

	XORQ AX, AX // clear flags
	
	MOVQ 32(BP), DX // rdx <-- y4
	MULXQ 0(SI), BX, CX // r4 <-- x0*y4
	ADOXQ 32(DI), BX
	MOVQ BX, 32(DI)
	MULXQ 8(SI), R8, R9 // r5 <-- x1*y4
	ADCXQ CX, R8
	ADOXQ 40(DI), R8
	MULXQ 16(SI), R10, R11 // r6 <-- x2*y4
	ADCXQ R9, R10
	ADOXQ 48(DI), R10
	MULXQ 24(SI), R12, R13 // r7 <-- x3*y4
	ADCXQ R11, R12
	ADOXQ 56(DI), R12
	MULXQ 32(SI), R14, R15 // r8 <-- x4*y4
	ADCXQ R13, R14
	ADOXQ 64(DI), R14

	// Consolidate both carry chains in R15, our final output.
	ADCXQ AX, R15
	ADOXQ AX, R15
	MOVQ R15, 72(DI)

	MOVQ R8, 40(DI)
	MOVQ R10, 48(DI)
	MOVQ R12, 56(DI)
	MOVQ R14, 64(DI)

	RET
