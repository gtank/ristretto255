// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ristretto255

import (
	"github.com/gtank/ristretto255/internal/scalar"
)

// A Scalar is an element of the ristretto255 scalar field, as specified in
// draft-hdevalence-cfrg-ristretto-01, Section 3.4. That is, an integer modulo
//
//     l = 2^252 + 27742317777372353535851937790883648493
type Scalar struct {
	s scalar.Scalar
}

// Add sets s = x + y mod l and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	s.s.Add(&x.s, &y.s)
	return s
}

// Sub sets s = x - y mod l and returns s.
func (s *Scalar) Sub(x, y *Scalar) *Scalar {
	s.s.Sub(&x.s, &y.s)
	return s
}

// Neg sets s = -x mod l and returns s.
func (s *Scalar) Neg(x *Scalar) *Scalar {
	s.s.Neg(&x.s)
	return s
}

// Mul sets s = x * y mod l and returns s.
func (s *Scalar) Mul(x, y *Scalar) *Scalar {
	s.s.Mul(&x.s, &y.s)
	return s
}

// FromUniformBytes sets s to an uniformly distributed value given 64 uniformly
// distributed random bytes.
func (s *Scalar) FromUniformBytes(x []byte) *Scalar {
	s.s.FromUniformBytes(x)
	return s
}

// Decode sets s = x, where x is a 32 bytes little-endian encoding of s. If x is
// not a canonical encoding of s, Decode returns an error and the receiver is
// unchanged.
func (s *Scalar) Decode(x []byte) error {
	return s.s.FromCanonicalBytes(x)
}

// Encode appends a 32 bytes little-endian encoding of s to b.
func (s *Scalar) Encode(b []byte) []byte {
	return s.s.Bytes(b)
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (s *Scalar) Equal(u *Scalar) int {
	return s.s.Equal(&u.s)
}

// Zero sets s = 0 and returns s.
func (s *Scalar) Zero() *Scalar {
	s.s = scalar.Scalar{}
	return s
}
