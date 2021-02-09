// Copyright (c) 2017 George Tankersley. All rights reserved.
// Copyright (c) 2021 Oasis Labs Inc.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!purego

package radix51

import "golang.org/x/sys/cpu"

var useBMI2 bool

// In an ideal world, this would have a function for basic amd64
// assembly, and one that uses BMI2.  The inliner fails to inline a
// function consisting of a single if/else statement, killing the
// performance gained by using BMI2 in the first place.
//
// This horrendous inliner behavior was last checked on Go 1.15.7.

//go:noescape
func feMulAmd64(out, a, b *FieldElement, useBMI2 bool)

//go:noescape
func feSquare(out, x *FieldElement)

func feMul(out, a, b *FieldElement) {
	feMulAmd64(out, a, b, useBMI2)
}

func init() {
	useBMI2 = cpu.Initialized && cpu.X86.HasBMI2
}
