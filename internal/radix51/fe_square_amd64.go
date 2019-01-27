// Copyright (c) 2017 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!noasm

package radix51

// Square sets v = x * x.
func (v *FieldElement) Square(x *FieldElement) {
	feSquare(v, x)
}

// go:noescape
func feSquare(out, x *FieldElement)
