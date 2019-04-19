// Copyright 2019 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ristretto255 implements the ristretto255 prime-order group as
// specified in draft-hdevalence-cfrg-ristretto-00.
package ristretto255

import (
	"github.com/gtank/ristretto255/internal/edwards25519"
	"github.com/gtank/ristretto255/internal/radix51"
)

var (
	sqrtM1 = fieldElementFromDecimal(
		"19681161376707505956807079304988542015446066515923890162744021073123829784752")
	sqrtADMinusOne = fieldElementFromDecimal(
		"25063068953384623474111414158702152701244531502492656460079210482610430750235")
	invSqrtAMinusD = fieldElementFromDecimal(
		"54469307008909316920995813868745141605393597292927456921205312896311721017578")
	oneMinusDSQ = fieldElementFromDecimal(
		"1159843021668779879193775521855586647937357759715417654439879720876111806838")
	dMinusOneSQ = fieldElementFromDecimal(
		"40440834346308536858101042469323190826248399146238708352240133220865137265952")
)

// Element is an element of the ristretto255 prime-order group.
type Element struct {
	r edwards25519.ExtendedGroupElement
}

// Equal returns 1 if e is equivalent to ee, and 0 otherwise.
// Note that Elements must not be compared in any other way.
func (e *Element) Equal(ee *Element) int {
	var f0, f1 radix51.FieldElement

	f0.Mul(&e.r.X, &ee.r.Y) // x1 * y2
	f1.Mul(&e.r.Y, &ee.r.X) // y1 * x2
	out := f0.Equal(&f1)

	f0.Mul(&e.r.Y, &ee.r.Y) // y1 * y2
	f1.Mul(&e.r.X, &ee.r.X) // x1 * x2
	out = out | f0.Equal(&f1)

	return out
}

// FromUniformBytes maps the 64-byte slice b to an Element e uniformly and
// deterministically. This can be used for hash-to-group operations or to obtain
// a random element.
func (e *Element) FromUniformBytes(b []byte) {
	if len(b) != 64 {
		panic("ristretto255: FromUniformBytes: input is not 64 bytes long")
	}

	f := &radix51.FieldElement{}

	f.FromBytes(b[:32])
	p1 := &edwards25519.ExtendedGroupElement{}
	mapToPoint(p1, f)

	f.FromBytes(b[32:])
	p2 := &edwards25519.ExtendedGroupElement{}
	mapToPoint(p2, f)

	e.r.Add(p1, p2)
}

// mapToPoint implements MAP from Section 3.2.4 of draft-hdevalence-cfrg-ristretto-00.
func mapToPoint(out *edwards25519.ExtendedGroupElement, t *radix51.FieldElement) {
	// r = SQRT_M1 * t^2
	r := &radix51.FieldElement{}
	r.Mul(sqrtM1, r.Square(t))

	// u = (r + 1) * ONE_MINUS_D_SQ
	u := &radix51.FieldElement{}
	u.Mul(u.Add(r, radix51.One), oneMinusDSQ)

	// c = -1
	c := &radix51.FieldElement{}
	c.Set(radix51.MinusOne)

	// v = (c - r*D) * (r + D)
	rPlusD := &radix51.FieldElement{}
	rPlusD.Add(r, edwards25519.D)
	v := &radix51.FieldElement{}
	v.Mul(v.Sub(c, v.Mul(r, edwards25519.D)), rPlusD)

	// (was_square, s) = SQRT_RATIO_M1(u, v)
	s := &radix51.FieldElement{}
	wasSquare := feSqrtRatio(s, u, v)

	// s_prime = -CT_ABS(s*t)
	sPrime := &radix51.FieldElement{}
	sPrime.Neg(sPrime.Abs(sPrime.Mul(s, t)))

	// s = CT_SELECT(s IF was_square ELSE s_prime)
	s.Select(s, sPrime, wasSquare)
	// c = CT_SELECT(c IF was_square ELSE r)
	c.Select(c, r, wasSquare)

	// N = c * (r - 1) * D_MINUS_ONE_SQ - v
	N := &radix51.FieldElement{}
	N.Mul(c, N.Sub(r, radix51.One))
	N.Sub(N.Mul(N, dMinusOneSQ), v)

	s2 := &radix51.FieldElement{}
	s2.Square(s)

	// w0 = 2 * s * v
	w0 := &radix51.FieldElement{}
	w0.Add(w0, w0.Mul(s, v))
	// w1 = N * SQRT_AD_MINUS_ONE
	w1 := &radix51.FieldElement{}
	w1.Mul(N, sqrtADMinusOne)
	// w2 = 1 - s^2
	w2 := &radix51.FieldElement{}
	w2.Sub(radix51.One, s2)
	// w3 = 1 + s^2
	w3 := &radix51.FieldElement{}
	w3.Add(radix51.One, s2)

	// return (w0*w3, w2*w1, w1*w3, w0*w2)
	out.X.Mul(w0, w3)
	out.Y.Mul(w2, w1)
	out.Z.Mul(w1, w3)
	out.T.Mul(w0, w2)
}
