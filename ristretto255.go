// Copyright 2016 The Go Authors. All rights reserved.
// Copyright 2019 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ristretto255 implements the ristretto255 prime-order group as
// specified in draft-hdevalence-cfrg-ristretto-00.
package ristretto255

import (
	"github.com/gtank/ristretto255/internal/edwards25519"
)

// Element is an element of the ristretto255 prime-order group.
type Element struct {
	r edwards25519.ExtendedGroupElement
}

// Equal returns 1 if e is equivalent to ee, and 0 otherwise.
// Note that Elements must not be compared in any other way.
func (e *Element) Equal(ee *Element) int {
	var f0, f1 edwards25519.FieldElement

	edwards25519.FeMul(&f0, &e.r.X, &ee.r.Y) // x1 * y2
	edwards25519.FeMul(&f1, &e.r.Y, &ee.r.X) // y1 * x2
	out := edwards25519.FeEqual(&f0, &f1)

	edwards25519.FeMul(&f0, &e.r.Y, &ee.r.Y) // y1 * y2
	edwards25519.FeMul(&f1, &e.r.X, &ee.r.X) // x1 * x2
	out = out | edwards25519.FeEqual(&f0, &f1)

	return out
}
