// Copyright (c) 2017 George Tankersley. All rights reserved.
// Copyright (c) 2021 Oasis Labs Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!purego

#include "textflag.h"

// reduce64 reduces the intermediaries stored in rsi, rbp, r8 .. r15.
//
// Inputs:   rsi, rbp, r8 .. r15.
// Clobbers: rax, rdx
#define reduce64() \
	MOVQ   $2251799813685247, AX \ // (1<<51) - 1
	SHLQ   $13, SI, BP           \ // r01 = shld with r00
	ANDQ   AX, SI                \ // r00 &= mask51
	SHLQ   $13, R8, R9           \ // r11 = shld with r10
	ANDQ   AX, R8                \ // r10 &= mask51
	ADDQ   BP, R8                \ // r10 += r01
	SHLQ   $13, R10, R11         \ // r21 = shld with r20
	ANDQ   AX, R10               \ // r20 &= mask51
	ADDQ   R9, R10               \ // r20 += r11
	SHLQ   $13, R12, R13         \ // r31 = shld with r30
	ANDQ   AX, R12               \ // r30 &= mask51
	ADDQ   R11, R12              \ // r30 += r21
	SHLQ   $13, R14, R15         \ // r41 = shld with r40
	ANDQ   AX, R14               \ // r40 &= mask51
	ADDQ   R13, R14              \ // r40 += r31
	IMUL3Q $19, R15, R15         \ // r41 = r41*19
	ADDQ   R15, SI               \ // r00 += r41
	                             \
	MOVQ   SI, DX                \ // rdx <-- r00
	SHRQ   $51, DX               \ // rdx <-- r00 >> 51
	ADDQ   DX, R8                \ // r10 += r00 >> 51
	MOVQ   R8, DX                \ // rdx <-- r10
	SHRQ   $51, DX               \ // rdx <-- r10 >> 51
	ANDQ   AX, SI                \ // r00 &= mask51
	ADDQ   DX, R10               \ // r20 += r10 >> 51
	MOVQ   R10, DX               \ // rdx <-- r20
	SHRQ   $51, DX               \ // rdx <-- r20 >> 51
	ANDQ   AX, R8                \ // r10 &= mask51
	ADDQ   DX, R12               \ // r30 += r20 >> 51
	MOVQ   R12, DX               \ // rdx <-- r30
	SHRQ   $51, DX               \ // rdx <-- r30 >> 51
	ANDQ   AX, R10               \ // r20 &= mask51
	ADDQ   DX, R14               \ // r40 += r30 >> 51
	MOVQ   R14, DX               \ // rdx <-- r40
	SHRQ   $51, DX               \ // rdx <-- r40 >> 51
	ANDQ   AX, R12               \ // r30 &= mask51
	IMUL3Q $19, DX, DX           \ // rdx <-- (r40 >> 51) * 19
	ADDQ   DX, SI                \ // r00 += (r40 >> 51) *19
	ANDQ   AX, R14               \ // r40 &= mask51

// func feMulAmd64(out, a, b *FieldElement, useBMI2 bool)
TEXT ·feMulAmd64(SB), NOSPLIT|NOFRAME, $0-25
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX

	MOVBQZX useBMI2+24(FP), DX
	TESTQ   DX, DX
	JZ      mul_vanilla

	// This codepath uses BMI2 to shave off a number of instructions,
	// for a slight performance gain.

	// r0 = a0*b0
	// r1 = a1*b0
	// r2 = a2*b0
	// r3 = a3*b0
	// r4 = a4*b0
	MOVQ  0(CX), DX        // rdx <- b0
	MULXQ 32(BX), R14, R15 // r40, r41 <- a4*b0
	MULXQ 24(BX), R12, R13 // r30, r31 <- a3*b0
	MULXQ 16(BX), R10, R11 // r20, r21 <- a2*b0
	MULXQ 8(BX), R8, R9    // r10, r11 <- a1*b0
	MULXQ 0(BX), SI, BP    // r00, r01 <- a0*b0

	// r0 += a4*b1_19
	// r1 += a0*b1
	// r2 += a1*b1
	// r3 += a2*b1
	// r4 += a3*b1
	MOVQ   8(CX), DX      // rdx <- b1
	MULXQ  24(BX), AX, DI // rdi, rax <- a3*b1
	ADDQ   AX, R14        // r40 += rax
	ADCQ   DI, R15        // r41 += rdi + cf
	MULXQ  16(BX), AX, DI // rdi, rax <- a2*b1
	ADDQ   AX, R12        // r30 += rax
	ADCQ   DI, R13        // r31 += rdi + cf
	MULXQ  8(BX), AX, DI  // rdi, rax <- a1*b1
	ADDQ   AX, R10        // r20 += rax
	ADCQ   DI, R11        // r21 += rdi + cf
	MULXQ  0(BX), AX, DI  // rdi, rax <- a0*b1
	ADDQ   AX, R8         // r10 += rax
	ADCQ   DI, R9         // r11 += rdi + cf
	IMUL3Q $19, DX, DX    // rdx <- b1*19
	MULXQ  32(BX), AX, DI // rdi, rax <- a4*b1_19
	ADDQ   AX, SI         // r00 += rax
	ADCQ   DI, BP         // r01 += rdi + cf

	// r0 += a3*b2_19
	// r1 += a4*b2_19
	// r2 += a0*b1
	// r3 += a1*b1
	// r4 += a2*b1
	MOVQ   16(CX), DX     // rdx <- b2
	MULXQ  16(BX), AX, DI // rdi, rax <= a2*b2
	ADDQ   AX, R14        // r40 += rax
	ADCQ   DI, R15        // r41 += rdi + cf
	MULXQ  8(BX), AX, DI  // rdi, rax <- a1*b2
	ADDQ   AX, R12        // r30 += rax
	ADCQ   DI, R13        // r31 += rdi + cf
	MULXQ  0(BX), AX, DI  // rdi, rax <- a0*b2
	ADDQ   AX, R10        // r20 += rax
	ADCQ   DI, R11        // r21 += rdi + cf
	IMUL3Q $19, DX, DX    // rdx <- b2*19
	MULXQ  32(BX), AX, DI // rdi, rax <- a4*b2_19
	ADDQ   AX, R8         // r10 += rax
	ADCQ   DI, R9         // r11 += rdi + cf
	MULXQ  24(BX), AX, DI // rdi, rax <- a3*b2_19
	ADDQ   AX, SI         // r00 += rax
	ADCQ   DI, BP         // r01 += rdi + cf

	// r0 += a2*b3_19
	// r1 += a3*b3_19
	// r2 += a4*b3_19
	// r3 += a0*b3
	// r4 += a1*b3
	MOVQ   24(CX), DX     // rdx <- b3
	MULXQ  8(BX), AX, DI  // rdi, rax <= a1*b3
	ADDQ   AX, R14        // r40 += rax
	ADCQ   DI, R15        // r41 += rdi + cf
	MULXQ  0(BX), AX, DI  // rdi, rax <- a0*b3
	ADDQ   AX, R12        // r30 += rax
	ADCQ   DI, R13        // r31 += rdi + cf
	IMUL3Q $19, DX, DX    // rdx <- b3*19
	MULXQ  32(BX), AX, DI // rdi, rax <- a4*b3_19
	ADDQ   AX, R10        // r20 += rax
	ADCQ   DI, R11        // r21 += rdi + cf
	MULXQ  24(BX), AX, DI // rdi, rax <- a3*b3_19
	ADDQ   AX, R8         // r10 += rax
	ADCQ   DI, R9         // r11 += rdi + cf
	MULXQ  16(BX), AX, DI // rdi, rax <- a2*b3_19
	ADDQ   AX, SI         // r00 += rax
	ADCQ   DI, BP         // r01 += rdi + cf

	// r0 += a1*b4_19
	// r1 += a2*b4_19
	// r2 += a3*b4_19
	// r3 += a4*b4_19
	// r4 += a0*b4
	MOVQ   32(CX), DX     // rdx <- b4
	MULXQ  0(BX), AX, DI  // rdi, rax <= a0*b4
	ADDQ   AX, R14        // r40 += rax
	ADCQ   DI, R15        // r41 += rdi + cf
	IMUL3Q $19, DX, DX    // rdx <- b4*19
	MULXQ  32(BX), AX, DI // rdi, rax <- a4*b4_19
	ADDQ   AX, R12        // r30 += rax
	ADCQ   DI, R13        // r31 += rdi + cf
	MULXQ  24(BX), AX, DI // rdi, rax <- a3*b4_19
	ADDQ   AX, R10        // r20 += rax
	ADCQ   DI, R11        // r21 += rdi + cf
	MULXQ  16(BX), AX, DI // rdi, rax <- a2*b4_19
	ADDQ   AX, R8         // r10 += rax
	ADCQ   DI, R9         // r11 += rdi + cf
	MULXQ  8(BX), AX, DI  // rdi, rax <- a1*b4_19
	ADDQ   AX, SI         // r00 += rax
	ADCQ   DI, BP         // r01 += rdi + cf

	JMP mul_reduce

mul_vanilla:

	// Based on assembly generated by PeachPy. Equivalent to the Go in
	// feMulGeneric, which was originally based on the amd64-51-30k
	// assembly in SUPERCOP.

	// Calculate r0
	MOVQ 0(BX), AX     // rax <-- x0
	MULQ 0(CX)         // rdx, rax <-- x0*y0
	MOVQ AX, SI        // r00 = rax
	MOVQ DX, BP        // r01 = rdx

	MOVQ 8(BX), DX     // rdx <-- x1
	IMUL3Q $19, DX, AX // rax <-- x1*19
	MULQ 32(CX)        // rdx, rax <-- x1_19*y4
	ADDQ AX, SI        // r00 += rax
	ADCQ DX, BP        // r01 += rdx

	MOVQ 16(BX), DX    // rdx <-- x2
	IMUL3Q $19, DX, AX // rax <-- x2*19
	MULQ 24(CX)        // rdx, rax <-- x2_19*y3
	ADDQ AX, SI        // r00 += rax
	ADCQ DX, BP        // r01 += rdx

	MOVQ 24(BX), DX    // rdx <-- x3
	IMUL3Q $19, DX, AX // rax <-- x3*19
	MULQ 16(CX)        // rdx, rax <-- x3_19 * y2
	ADDQ AX, SI        // r00 += rax
	ADCQ DX, BP        // r01 += rdx

	MOVQ 32(BX), DX    // rdx <-- x4
	IMUL3Q $19, DX, AX // rax <-- x4*19
	MULQ 8(CX)         // rdx rax <-- x4_19*y1
	ADDQ AX, SI        // r00 += rax
	ADCQ DX, BP        // r01 += rdx

	// Calculate r1
	MOVQ 0(BX), AX
	MULQ 8(CX)
	MOVQ AX, R8 // r10
	MOVQ DX, R9 // r11

	MOVQ 8(BX), AX
	MULQ 0(CX)
	ADDQ AX, R8
	ADCQ DX, R9

	MOVQ 16(BX), DX
	IMUL3Q $19, DX, AX
	MULQ 32(CX)
	ADDQ AX, R8
	ADCQ DX, R9

	MOVQ 24(BX), DX
	IMUL3Q $19, DX, AX
	MULQ 24(CX)
	ADDQ AX, R8
	ADCQ DX, R9

	MOVQ 32(BX), DX
	IMUL3Q $19, DX, AX
	MULQ 16(CX)
	ADDQ AX, R8
	ADCQ DX, R9

	// Calculate r2
	MOVQ 0(BX), AX
	MULQ 16(CX)
	MOVQ AX, R10 // r20
	MOVQ DX, R11 // r21

	MOVQ 8(BX), AX
	MULQ 8(CX)
	ADDQ AX, R10
	ADCQ DX, R11

	MOVQ 16(BX), AX
	MULQ 0(CX)
	ADDQ AX, R10
	ADCQ DX, R11

	MOVQ 24(BX), DX
	IMUL3Q $19, DX, AX
	MULQ 32(CX)
	ADDQ AX, R10
	ADCQ DX, R11

	MOVQ 32(BX), DX
	IMUL3Q $19, DX, AX
	MULQ 24(CX)
	ADDQ AX, R10
	ADCQ DX, R11

	// Calculate r3
	MOVQ 0(BX), AX
	MULQ 24(CX)
	MOVQ AX, R12 // r30
	MOVQ DX, R13 // r31

	MOVQ 8(BX), AX
	MULQ 16(CX)
	ADDQ AX, R12
	ADCQ DX, R13

	MOVQ 16(BX), AX
	MULQ 8(CX)
	ADDQ AX, R12
	ADCQ DX, R13

	MOVQ 24(BX), AX
	MULQ 0(CX)
	ADDQ AX, R12
	ADCQ DX, R13

	MOVQ 32(BX), DX
	IMUL3Q $19, DX, AX
	MULQ 32(CX)
	ADDQ AX, R12
	ADCQ DX, R13

	// Calculate r4
	MOVQ 0(BX), AX
	MULQ 32(CX)
	MOVQ AX, R14 // r40
	MOVQ DX, R15 // r41

	MOVQ 8(BX), AX
	MULQ 24(CX)
	ADDQ AX, R14
	ADCQ DX, R15

	MOVQ 16(BX), AX
	MULQ 16(CX)
	ADDQ AX, R14
	ADCQ DX, R15

	MOVQ 24(BX), AX
	MULQ 8(CX)
	ADDQ AX, R14
	ADCQ DX, R15

	MOVQ 32(BX), AX
	MULQ 0(CX)
	ADDQ AX, R14
	ADCQ DX, R15

mul_reduce:
	reduce64()

	MOVQ out+0(FP), DI
	MOVQ SI, 0(DI)
	MOVQ R8, 8(DI)
	MOVQ R10, 16(DI)
	MOVQ R12, 24(DI)
	MOVQ R14, 32(DI)
	RET

// func feSquareAmd64(out, x *FieldElement, useBMI2 bool)
TEXT ·feSquareAmd64(SB), NOSPLIT|NOFRAME, $0-17
    MOVQ x+8(FP), BX

	// Pick the appropriate implementation, based on if the caller thinks
	// BMI2 is supported or not.
	MOVBQZX useBMI2+16(FP), DX
	TESTQ   DX, DX
	JZ      square_vanilla

	// This codepath uses BMI2 to shave off a number of instructions,
	// for a slight performance gain.

	// r0 = a0*a0
	// r1 = 2*a0*a1
	// r2 = 2*a0*a2
	// r3 = 2*a0*a3
	// r4 = 2*a0*a4
	MOVQ  0(BX), DX        // rdx <- a0
	MULXQ DX, SI, BP       // r00, r01 <- a0*a0
	SHLQ  $1, DX           // rdx *= 2 (d0 = 2*a0)
	MULXQ 8(BX), R8, R9    // r10, r11 <- d0*a1
	MULXQ 16(BX), R10, R11 // r20, r21 <- d0*a2
	MULXQ 24(BX), R12, R13 // r30, r31 <- d0*a3
	MULXQ 32(BX), R14, R15 // r40, r41 <- d0*a4

	// r2 += a1*a1
	// r3 += 2*a1*a2
	// r4 += 2*a1*a3
	MOVQ   8(BX), DX      // rdx <- a1
	MULXQ  DX, AX, DI     // rdi, rax = a1*a1
	ADDQ   AX, R10        // r20 += rax
	ADCQ   DI, R11        // r21 += rdi + cf
	SHLQ   $1, DX         // rdx *= 2  (d1 = 2*a1)
	MULXQ  16(BX), AX, DI // rdi, rax = d1*a2
	ADDQ   AX, R12        // r30 += rax
	ADCQ   DI, R13        // r31 += rdi + cf
	MULXQ  24(BX), AX, DI // rdi, rax = d1*a3
	ADDQ   AX, R14        // r40 += rax
	ADCQ   DI, R15        // r41 += rdi + cf
	IMUL3Q $19, DX, DX    // rdx *= 19 (d1_38 = 2*19*a1)
	MULXQ  32(BX), AX, DI // rdi, rax = d1_38*a4
	ADDQ   AX, SI         // r00 += rax
	ADCQ   DI, BP         // r01 += rdi + cf

	// r4 += a2*a2
	// r0 += 2*19*a2*a3
	// r1 += 2*19*a2*a4
	MOVQ   16(BX), DX     // rdx <- a2
	MULXQ  DX, AX, DI     // rdi, rax = a2*a2
	ADDQ   AX, R14        // r40 += rax
	ADCQ   DI, R15        // r41 += rdi + cf
	IMUL3Q $38, DX, DX    // dx *= 2*19 (d2_38 = 2*19*a2)
	MULXQ  24(BX), AX, DI // rdi, rax = d2_38*a3
	ADDQ   AX, SI         // r00 += rax
	ADCQ   DI, BP         // r01 += rdi + cf
	MULXQ  32(BX), AX, DI // rdi, rax = d2_38*a4
	ADDQ   AX, R8         // r10 += rax
	ADCQ   DI, R9         // r11 += rdi + cf

	// r1 += 19*a3*a3
	// r2 += 2*19*a4*a3
	MOVQ   24(BX), DX     // rdx <- a3
	IMUL3Q $19, DX, DX    // dx *= 19 (d3_19 = 19*a3)
	MULXQ  24(BX), AX, DI // rdi, rax = d3_19*a3
	ADDQ   AX, R8         // r10 += rax
	ADCQ   DI, R9         // r11 += rdi + cf
	SHLQ   $1, DX         // rdx *= 2  (d3_38 = 2*19*a3)
	MULXQ  32(BX), AX, DI // rdi, rax = d3_38*a4
	ADDQ   AX, R10        // r20 += rax
	ADCQ   DI, R11        // r21 += rdi + cf

	// r3 += 19*a4*a4
	MOVQ   32(BX), DX     // rdx <- a4
	IMUL3Q $19, DX, DX    // dx *= 19 (d4_19 = 19*a4)
	MULXQ  32(BX), AX, DI // rdi, rax = d4_19*a4
	ADDQ   AX, R12        // r30 += rax
	ADCQ   DI, R13        // r31 += rdi + cf

	JMP square_reduce

square_vanilla:

    // r0 = x0*x0 + x1*38*x4 + x2*38*x3
    MOVQ 0(BX), AX
    MULQ 0(BX)
    MOVQ AX, SI // r00
    MOVQ DX, BP // r01

    MOVQ 8(BX), DX
    IMUL3Q $38, DX, AX
    MULQ 32(BX)
    ADDQ AX, SI
    ADCQ DX, BP

    MOVQ 16(BX), DX
    IMUL3Q $38, DX, AX
    MULQ 24(BX)
    ADDQ AX, SI
    ADCQ DX, BP

    // r1 = x0*2*x1 + x2*38*x4 + x3*19*x3
    MOVQ 0(BX), AX
    SHLQ $1, AX
    MULQ 8(BX)
    MOVQ AX, R8  // r10
    MOVQ DX, R9 // r11

    MOVQ 16(BX), DX
    IMUL3Q $38, DX, AX
    MULQ 32(BX)
    ADDQ AX, R8
    ADCQ DX, R9

    MOVQ 24(BX), DX
    IMUL3Q $19, DX, AX
    MULQ 24(BX)
    ADDQ AX, R8
    ADCQ DX, R9

    // r2 = x0*2*x2 + x1*x1 + x3*38*x4
    MOVQ 0(BX), AX
    SHLQ $1, AX
    MULQ 16(BX)
    MOVQ AX, R10 // r20
    MOVQ DX, R11 // r21

    MOVQ 8(BX), AX
    MULQ 8(BX)
    ADDQ AX, R10
    ADCQ DX, R11

    MOVQ 24(BX), DX
    IMUL3Q $38, DX, AX
    MULQ 32(BX)
    ADDQ AX, R10
    ADCQ DX, R11

    // r3 = x0*2*x3 + x1*2*x2 + x4*19*x4
    MOVQ 0(BX), AX
    SHLQ $1, AX
    MULQ 24(BX)
    MOVQ AX, R12 // r30
    MOVQ DX, R13 // r31

    MOVQ 8(BX), AX
    SHLQ $1, AX
    MULQ 16(BX)
    ADDQ AX, R12
    ADCQ DX, R13

    MOVQ 32(BX), DX
    IMUL3Q $19, DX, AX
    MULQ 32(BX)
    ADDQ AX, R12
    ADCQ DX, R13

    // r4 = x0*2*x4 + x1*2*x3 + x2*x2
    MOVQ 0(BX), AX
    SHLQ $1, AX
    MULQ 32(BX)
    MOVQ AX, R14 // r40
    MOVQ DX, R15  // r41

    MOVQ 8(BX), AX
    SHLQ $1, AX
    MULQ 24(BX)
    ADDQ AX, R14
    ADCQ DX, R15

    MOVQ 16(BX), AX
    MULQ 16(BX)
    ADDQ AX, R14
    ADCQ DX, R15

square_reduce:
    // Reduce
    reduce64()

    MOVQ out+0(FP), DI
	MOVQ SI, 0(DI)
	MOVQ R8, 8(DI)
	MOVQ R10, 16(DI)
	MOVQ R12, 24(DI)
	MOVQ R14, 32(DI)

    RET
