// Copyright 2019 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ristretto255

import (
	"math/big"

	. "github.com/gtank/ristretto255/internal/radix51"
)

// fePow22523 is from x/crypto/ed25519/internal/edwards25519.
func fePow22523(out, z *FieldElement) {
	var t0, t1, t2 FieldElement
	var i int

	FeSquare(&t0, z)
	for i = 1; i < 1; i++ {
		FeSquare(&t0, &t0)
	}
	FeSquare(&t1, &t0)
	for i = 1; i < 2; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t1, z, &t1)
	FeMul(&t0, &t0, &t1)
	FeSquare(&t0, &t0)
	for i = 1; i < 1; i++ {
		FeSquare(&t0, &t0)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t1, &t0)
	for i = 1; i < 5; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t1, &t0)
	for i = 1; i < 10; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t1, &t1, &t0)
	FeSquare(&t2, &t1)
	for i = 1; i < 20; i++ {
		FeSquare(&t2, &t2)
	}
	FeMul(&t1, &t2, &t1)
	FeSquare(&t1, &t1)
	for i = 1; i < 10; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t1, &t0)
	for i = 1; i < 50; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t1, &t1, &t0)
	FeSquare(&t2, &t1)
	for i = 1; i < 100; i++ {
		FeSquare(&t2, &t2)
	}
	FeMul(&t1, &t2, &t1)
	FeSquare(&t1, &t1)
	for i = 1; i < 50; i++ {
		FeSquare(&t1, &t1)
	}
	FeMul(&t0, &t1, &t0)
	FeSquare(&t0, &t0)
	for i = 1; i < 2; i++ {
		FeSquare(&t0, &t0)
	}
	FeMul(out, &t0, z)
}

func feSqrtRatio(out, u, v *FieldElement) int {
	var a, b FieldElement

	// v^3, v^7
	v3, v7 := &a, &b

	FeSquare(v3, v)  // v^2 = v*v
	FeMul(v3, v3, v) // v^3 = v^2 * v
	FeSquare(v7, v3) // v^6 = v^3 * v^3
	FeMul(v7, v7, v) // v^7 = v^6 * v

	// r = (u * v3) * (u * v7)^((p-5)/8)
	r := out
	uv3, uv7 := v3, v7   // alias
	FeMul(uv3, u, v3)    // (u * v3)
	FeMul(uv7, u, v7)    // (u * v7)
	fePow22523(uv7, uv7) // (u * v7) ^ ((q - 5)/8)
	FeMul(r, uv3, uv7)

	// done with these ("freeing" a, b)
	v3, v7, uv3, uv7 = nil, nil, nil, nil

	// check = v * r^2
	check := &a
	FeMul(check, r, r)     // r^2
	FeMul(check, check, v) // v * r^2

	uneg := &b
	FeNeg(uneg, u)
	correct_sign_sqrt := FeEqual(check, u)
	flipped_sign_sqrt := FeEqual(check, uneg)
	FeMul(uneg, uneg, sqrtM1)
	flipped_sign_sqrt_i := FeEqual(check, uneg)

	// done with these ("freeing" a, b)
	check, uneg = nil, nil

	// r_prime = SQRT_M1 * r
	// r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
	r_prime := &a
	FeMul(r_prime, r, sqrtM1)
	FeSelect(r, r_prime, r, flipped_sign_sqrt|flipped_sign_sqrt_i)

	FeAbs(r, r)
	was_square := correct_sign_sqrt | flipped_sign_sqrt

	return was_square
}

func fieldElementFromDecimal(s string) *FieldElement {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("ristretto255: not a valid decimal: " + s)
	}
	var fe FieldElement
	FeFromBig(&fe, n)
	return &fe
}
