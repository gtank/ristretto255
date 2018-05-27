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

	MOVQ 0(BP), DX // rdx <-- y0
	MULXQ 0(SI), R8, R9 // r0 <-- x0*y0
	MULXQ 8(SI), R10, R11 // r1 <-- x1*y0
	ADDQ R9, R10
	MULXQ 16(SI), R12, R13 // r2 <-- x2*y0
	ADCQ R11, R12
	MULXQ 24(SI), R14, R15 // r3 <-- x3*y0
	ADCQ R13, R14
	MULXQ 32(SI), BX, CX // r4 <-- x4*y0
	ADCQ R15, BX

	// CX is R[5], so we multiply by 19 add it to R[0]
	ADCQ $0, CX
	IMUL3Q $19, CX, AX
	ADDQ AX, R8

	// Now we have R8,R10,R12,R14,BX as R[4:0] and CX handled by our reduction
	// identity. Since we can use offset addressing directly with ADD
	// instructions, store the accumulators in the output to free up registers
	// for more MULX results.

	MOVQ R8, 0(DI)
	MOVQ R10, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)

	XORQ AX, AX // clear flags

	MOVQ 8(BP), DX // rdx <-- y1
	MULXQ 0(SI), R10, R11 // r1 <-- x0*y1
	//ADCXQ $0, R10 // this is a NOP
	ADOXQ 8(DI), R10
	MULXQ 8(SI), R12, R13 // r2 <-- x1*y1
	ADCXQ R11, R12
	ADOXQ 16(DI), R12
	MULXQ 16(SI), R14, R15 // r3 <-- x2*y1
	ADCXQ R13, R14
	ADOXQ 24(DI), R14
	MULXQ 24(SI), BX, CX // r4 <-- x3*y1
	ADCXQ R15, BX
	ADOXQ 32(DI), BX
	MULXQ 32(SI), R8, R9 // r0 = r5*19 <-- 19*(x4*y1)
	ADCXQ CX, R8
	ADOXQ 0(DI), R8

	// Consolidate both carry chains in R9 then add it to R[6] mapped to R[1]
	// by the reduction identity.
	ADCXQ AX, R9
	ADOXQ AX, R9
	IMUL3Q $19, R9, AX
	ADDQ AX, R10

	// Update accumulators
	MOVQ R8, 0(DI)
	MOVQ R10, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)

	XORQ AX, AX // clear flags

	MOVQ 16(BP), DX // rdx <-- y2
	MULXQ 0(SI), R12, R13 // r2 <-- x0*y2
	//ADCXQ $0, R12 // this is a NOP
	ADOXQ 16(DI), R12
	MULXQ 8(SI), R14, R15 // r3 <-- x1*y2
	ADCXQ R13, R14
	ADOXQ 24(DI), R14
	MULXQ 16(SI), BX, CX // r4 <-- x2*y2
	ADCXQ R15, BX
	ADOXQ 32(DI), BX
	MULXQ 24(SI), R8, R9 // r0 = r5*19 <-- 19*(x3*y2)
	ADCXQ CX, R8
	IMUL3Q $19, R8, R8
	ADOXQ 0(DI), R8
	MULXQ 32(SI), R10, R11 // r1 = r6*19 <-- 19*(x4*y2)
	ADCXQ R9, R10
	IMUL3Q $19, R10, R10
	ADOXQ 8(DI), R10

	// Consolidate both carry chains in R11 then add it to R[7] mapped to R[2].
	ADCXQ AX, R11
	ADOXQ AX, R11
	IMUL3Q $19, R11, AX
	ADDQ AX, R12

	// Update accumulators
	MOVQ R8, 0(DI)
	MOVQ R10, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)

	XORQ AX, AX // clear flags

	MOVQ 24(BP), DX // rdx <-- y3
	MULXQ 0(SI), R14, R15 // r3 <-- x0*y3
	//ADCXQ $0, R14 // this is a NOP
	ADOXQ 24(DI), R14
	MULXQ 8(SI), BX, CX // r4 <-- x1*y3
	ADCXQ R15, BX
	ADOXQ 32(DI), BX
	MULXQ 16(SI), R8, R9 // r0 = r5*19 <-- 19*(x2*y3)
	ADCXQ CX, R8
	IMUL3Q $19, R8, R8
	ADOXQ 0(DI), R8
	MULXQ 24(SI), R10, R11 // r1 = r6*19 <-- 19*(x3*y3)
	ADCXQ R9, R10
	IMUL3Q $19, R10, R10
	ADOXQ 8(DI), R10
	MULXQ 32(SI), R12, R13 // r2 = r7*19 <-- 19*(x4*y3)
	ADCXQ R11, R12
	IMUL3Q $19, R12, R12
	ADOXQ 16(DI), R12

	// Consolidate both carry chains in R13 then add it to R[8] mapped to R[3].
	ADCXQ AX, R13
	ADOXQ AX, R13
	IMUL3Q $19, R13, AX
	ADDQ AX, R14

	// Update accumulators
	MOVQ R8, 0(DI)
	MOVQ R10, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)

	XORQ AX, AX // clear flags

	MOVQ 32(BP), DX // rdx <-- y4

	MULXQ 0(SI), BX, CX // r4 <-- x0*y4
	//ADCXQ $0, BX // this is a NOP
	ADOXQ 32(DI), BX
	
	MULXQ 8(SI), R8, R9 // r0 = r5*19 <-- 19*(x1*y4)
	ADCXQ CX, R8
	IMUL3Q $19, R8, R8
	ADOXQ 0(DI), R8

	MULXQ 16(SI), R10, R11 // r1 = r6*19 <-- 19*(x2*y4)
	ADCXQ R9, R10
	IMUL3Q $19, R10, R10
	ADOXQ 8(DI), R10

	MULXQ 24(SI), R12, R13 // r2 = r7*19 <-- 19*(x3*y4)
	ADCXQ R11, R12
	IMUL3Q $19, R12, R12
	ADOXQ 16(DI), R12

	MULXQ 32(SI), R14, R15 // r3 = r8*19 <-- 19*(x4*y4)
	ADCXQ R13, R14
	IMUL3Q $19, R14, R14
	ADOXQ 24(DI), R14

	// Consolidate both carry chains in R15 then add it to R[9] mapped to R[4]
	ADCXQ AX, R15
	ADOXQ AX, R15
	IMUL3Q $19, R15, AX
	ADDQ AX, BX

	// Update accumulators
	MOVQ R8, 0(DI)
	MOVQ R10, 8(DI)
	MOVQ R12, 16(DI)
	MOVQ R14, 24(DI)
	MOVQ BX, 32(DI)

	RET
