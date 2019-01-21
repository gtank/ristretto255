// Copyright 2019 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ristretto255 implements the ristretto255 prime-order group as
// specified in draft-hdevalence-cfrg-ristretto-00.
package ristretto255

import (
	"github.com/gtank/ristretto255/internal/group"
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
	r group.ExtendedGroupElement
}

// Equal returns 1 if e is equivalent to ee, and 0 otherwise.
// Note that Elements must not be compared in any other way.
func (e *Element) Equal(ee *Element) int {
	var f0, f1 radix51.FieldElement

	radix51.FeMul(&f0, &e.r.X, &ee.r.Y) // x1 * y2
	radix51.FeMul(&f1, &e.r.Y, &ee.r.X) // y1 * x2
	out := radix51.FeEqual(&f0, &f1)

	radix51.FeMul(&f0, &e.r.Y, &ee.r.Y) // y1 * y2
	radix51.FeMul(&f1, &e.r.X, &ee.r.X) // x1 * x2
	out = out | radix51.FeEqual(&f0, &f1)

	return out
}

// FromUniformBytes maps the 64-byte slice b to an Element e uniformly and
// deterministically. This can be used for hash-to-group operations or to obtain
// a random element.
func (e *Element) FromUniformBytes(b []byte) {
	if len(b) != 64 {
		panic("ristretto255: FromUniformBytes: input is not 64 bytes long")
	}

	panic("ristretto255: FromUniformBytes: unimplemented")
}
