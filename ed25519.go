// Copyright (c) 2017 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519 implements an elliptic.Curve interface on top of the twisted
// Edwards curve -x^2 + y^2 = 1 + -(121665/121666)*x^2*y^2. This is better
// known as the Edwards curve equivalent to curve25519, and is the curve used
// by the Ed25519 signature scheme.
//
// Because of the Curve interface, this package takes input in affine (x,y)
// pairs instead of the more standard compressed Edwards y.
package ed25519

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/gtank/ed25519/internal/group"
	"github.com/gtank/ed25519/internal/radix51"
)

var bigZero *big.Int
var bigOne *big.Int

type ed25519Curve struct {
	*elliptic.CurveParams
}

var once sync.Once
var ed25519Params = &elliptic.CurveParams{Name: "ed25519"}
var ed25519 = ed25519Curve{ed25519Params}

// Ed25519 uses a twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 with the following params:
// The field prime is 2^255 - 19.
// The order of the base point is 2^252 + 27742317777372353535851937790883648493.
// And since B is irrelevant here, we're going to pretend that B is d = -(121665/121666).
func initEd25519Params() {
	ed25519Params.P, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	ed25519Params.N, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	ed25519Params.B, _ = new(big.Int).SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)
	ed25519Params.Gx, _ = new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	ed25519Params.Gy, _ = new(big.Int).SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)
	ed25519Params.BitSize = 256
	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)
}

// Ed25519 returns a Curve that implements Ed25519.
func Ed25519() elliptic.Curve {
	once.Do(initEd25519Params)
	return ed25519
}

// Params returns the parameters for the curve.
func (curve ed25519Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// IsOnCurve reports whether the given (x,y) lies on the curve by checking that
// -x^2 + y^2 - 1 - dx^2y^2 = 0 (mod p). This function uses a hardcoded value
// of d.
func (curve ed25519Curve) IsOnCurve(x, y *big.Int) bool {
	var feX, feY radix51.FieldElement
	feX.FromBig(x)
	feY.FromBig(y)

	var lh, y2, rh radix51.FieldElement
	lh.Square(&feX)          // x^2
	y2.Square(&feY)          // y^2
	rh.Mul(&lh, &y2)         // x^2*y^2
	rh.Mul(&rh, group.D)     // d*x^2*y^2
	rh.Add(&rh, radix51.One) // 1 + d*x^2*y^2
	lh.Neg(&lh)              // -x^2
	lh.Add(&lh, &y2)         // -x^2 + y^2
	lh.Sub(&lh, &rh)         // -x^2 + y^2 - 1 - dx^2y^2
	lh.Reduce(&lh)           // mod p

	return lh.Equal(radix51.Zero) == 1
}

// Add returns the sum of (x1, y1) and (x2, y2).
func (curve ed25519Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	var p1, p2 group.ExtendedGroupElement

	p1.FromAffine(x1, y1)
	p2.FromAffine(x2, y2)

	return p2.Add(&p1, &p2).ToAffine()
}

// Double returns 2*(x,y).
func (curve ed25519Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	p := new(group.ProjectiveGroupElement).FromAffine(x1, y1)
	// Use the special-case DoubleZ1 here because we know Z will be 1.
	return p.DoubleZ1(p).ToAffine()
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (curve ed25519Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	// if either coordinate is nil, return the identity point
	if x1 == nil || y1 == nil {
		x = new(big.Int).Set(bigZero)
		y = new(big.Int).Set(bigOne)
		return
	}

	var r0, r1 group.ExtendedGroupElement
	var s [32]byte

	curve.scalarFromBytes(&s, k)

	// Montgomery ladder init:
	// R_0 = O, R_1 = P
	r0.Zero()
	r1.FromAffine(x1, y1)

	// Montgomery ladder step:
	// R_{1-b} = R_{1-b} + R_{b}
	// R_{b} = 2*R_{b}
	for i := 255; i >= 0; i-- {
		var b = int32((s[i/8] >> uint(i&7)) & 1)
		if b == 0 {
			r1.Add(&r0, &r1)
			r0.Double(&r0)
		} else {
			r0.Add(&r0, &r1)
			r1.Double(&r0)
		}
	}

	return r0.ToAffine()
}

// scalarFromBytes converts a big-endian value to a fixed-size little-endian
// representation. If the value is larger than the scalar group order, we
// reduce it before returning.
func (curve ed25519Curve) scalarFromBytes(out *[32]byte, in []byte) {
	scalar := new(big.Int).SetBytes(in)
	if scalar.Cmp(curve.N) >= 0 {
		scalar.Mod(scalar, curve.N)
	}
	buf := make([]byte, 32)
	scBytes := scalar.Bytes()
	copy(buf[32-len(scBytes):], scBytes)
	for i := 0; i < 32; i++ {
		out[i] = buf[31-i]
	}
}

// ScalarBaseMult returns k*G, where G is the base point of the curve and k is
// an integer in big-endian form. The difference between this and
// arbitrary-point ScalarMult is the availability of precomputed multiples of
// the base point.
func (curve ed25519Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	panic("not yet implemented")
}
