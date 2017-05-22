// Implements an elliptic.Curve interface over the ed25519 curve.
package ed25519

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/gtank/ed25519/internal/edwards25519"
)

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
}

func Ed25519() elliptic.Curve {
	once.Do(initEd25519Params)
	return ed25519
}

// Params returns the parameters for the curve.
func (curve ed25519Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// IsOnCurve reports whether the given (x,y) lies on the curve by checking that
// -x^2 + y^2 - 1 - dx^2y^2 = 0.
func (curve ed25519Curve) IsOnCurve(x, y *big.Int) bool {
	lh := new(big.Int).Mul(x, x)   // x^2
	y2 := new(big.Int).Mul(y, y)   // y^2
	rh := new(big.Int).Mul(lh, y2) // x^2y^2
	rh.Mul(rh, curve.B)            // dx^2y^2 with B repurposed as d
	rh.Add(rh, bigOne)             // 1 + dx^2y^2
	lh.Neg(lh)                     // -x^2
	lh.Add(lh, y2)                 // -x^2 + y^2
	lh.Sub(lh, rh)                 // -x^2 + y^2 - 1 - dx^2y^2
	lh.Mod(lh, curve.P)            // -x^2 + y^2 - 1 - dx^2y^2 mod p
	return lh.Cmp(bigZero) == 0
}

// Add returns the sum of (x1, y1) and (x2, y2).
func (curve ed25519Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	var p1, p2, p3 edwards25519.ExtendedGroupElement

	affineToExtended(&p1, x1, y1)
	affineToExtended(&p2, x2, y2)
	extendedAdd(&p3, &p1, &p2)

	return extendedToAffine(&p3) // 1I + 2M
}

// The internal edwards25519 package optimizes for a particular sequence of
// operations, so we reimplement addition (add-2008-hwcd-3) here to avoid the
// cost of converting between intermediate representations.
// TODO We know Z1=1 and Z2=1 here, so mmadd-2008-hwcd-3 (6M + 1S + 1*k + 9add) could apply
func extendedAdd(out, p1, p2 *edwards25519.ExtendedGroupElement) {
	var tmp1, tmp2, A, B, C, D, E, F, G, H edwards25519.FieldElement

	edwards25519.FeSub(&tmp1, &p1.Y, &p1.X) // tmp1 <-- Y1-X1
	edwards25519.FeSub(&tmp2, &p2.Y, &p2.X) // tmp2 <-- Y2-X2
	edwards25519.FeMul(&A, &tmp1, &tmp2)    // A <-- tmp1*tmp2 = (Y1-X1)*(Y2-X2)
	edwards25519.FeAdd(&tmp1, &p1.Y, &p1.X) // tmp1 <-- Y1+X1
	edwards25519.FeAdd(&tmp2, &p2.Y, &p2.X) // tmp2 <-- Y2+X2
	edwards25519.FeMul(&B, &tmp1, &tmp2)    // B <-- tmp1*tmp2 = (Y1+X1)*(Y2+X2)
	edwards25519.FeMul(&tmp1, &p1.T, &p2.T) // tmp1 <-- T1*T2
	edwards25519.FeMul(&C, &tmp1, &d2)      // C <-- tmp1*2d = T1*2d*T2
	edwards25519.FeMul(&tmp1, &p1.Z, &p2.Z) // tmp1 <-- Z1*Z2
	edwards25519.FeAdd(&D, &tmp1, &tmp1)    // D <-- tmp1 + tmp1 = 2*Z1*Z2
	edwards25519.FeSub(&E, &B, &A)          // E <-- B-A
	edwards25519.FeSub(&F, &D, &C)          // F <-- D-C
	edwards25519.FeAdd(&G, &D, &C)          // G <-- D+C
	edwards25519.FeAdd(&H, &B, &A)          // H <-- B+A
	edwards25519.FeMul(&out.X, &E, &F)      // X3 <-- E*F
	edwards25519.FeMul(&out.Y, &G, &H)      // Y3 <-- G*H
	edwards25519.FeMul(&out.T, &E, &H)      // T3 <-- E*H
	edwards25519.FeMul(&out.Z, &F, &G)      // Z3 <-- F*G
}

// Double returns 2*(x,y).
// TODO: cheaper to reimplement? the typed path is aff->proj->completed->proj->aff
func (curve ed25519Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	var p edwards25519.ProjectiveGroupElement
	var r edwards25519.CompletedGroupElement
	affineToProjective(&p, x1, y1)
	p.Double(&r)
	r.ToProjective(&p)            // 3M
	return projectiveToAffine(&p) // 1I + 2M
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (curve ed25519Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	// if either coordinate is nil, return the point at infinity
	if x1 == nil || y1 == nil {
		x = new(big.Int).Set(bigZero)
		y = new(big.Int).Set(bigOne)
		return
	}

	var r0, r1 edwards25519.ExtendedGroupElement
	var h edwards25519.CompletedGroupElement
	var s [32]byte

	curve.scalarFromBytes(&s, k)

	// Montgomery ladder init:
	// R_0 = O, R_1 = P
	r0.Zero()
	affineToExtended(&r1, x1, y1)

	// Montgomery ladder step:
	// R_{1-b} = R_{1-b} + R_{b}
	// R_{b} = 2*R_{b}
	for i := 255; i >= 0; i-- {
		var b = int32((s[i/8] >> uint(i&7)) & 1)
		if b == 0 {
			extendedAdd(&r1, &r0, &r1)
			r0.Double(&h)
			h.ToExtended(&r0)
		} else {
			extendedAdd(&r0, &r0, &r1)
			r1.Double(&h)
			h.ToExtended(&r1)
		}
	}

	return extendedToAffine(&r0)
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

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (curve ed25519Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	var p edwards25519.ExtendedGroupElement
	var scBytes [32]byte

	curve.scalarFromBytes(&scBytes, k)
	edwards25519.GeScalarMultBase(&p, &scBytes)
	return extendedToAffine(&p)
}

// Converts (x,y) to (X:Y:T:Z) extended coordinates, or "P3" in ref10. As
// described in "Twisted Edwards Curves Revisited", Hisil-Wong-Carter-Dawson
// 2008, Section 3.1 (https://eprint.iacr.org/2008/522.pdf)
// See also https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
func affineToExtended(out *edwards25519.ExtendedGroupElement, x, y *big.Int) {
	feFromBig(&out.X, x)
	feFromBig(&out.Y, y)
	edwards25519.FeMul(&out.T, &out.X, &out.Y)
	edwards25519.FeOne(&out.Z)
}

// Extended coordinates are XYZT with x = X/Z, y = Y/Z, or the "P3"
// representation in ref10. Extended->affine is the same operation as moving
// from projective to affine. Per HWCD, it is safe to move from extended to
// projective by simply ignoring T.
func extendedToAffine(in *edwards25519.ExtendedGroupElement) (*big.Int, *big.Int) {
	var x, y, zinv edwards25519.FieldElement
	var bigX, bigY = new(big.Int), new(big.Int)

	edwards25519.FeInvert(&zinv, &in.Z)
	edwards25519.FeMul(&x, &in.X, &zinv)
	edwards25519.FeMul(&y, &in.Y, &zinv)

	feToBig(bigX, &x)
	feToBig(bigY, &y)

	return bigX, bigY
}

// Projective coordinates are XYZ with x = X/Z, y = Y/Z, or the "P2" representation in ref10.
func affineToProjective(out *edwards25519.ProjectiveGroupElement, x, y *big.Int) {
	feFromBig(&out.X, x)
	feFromBig(&out.Y, y)
	edwards25519.FeOne(&out.Z)
}

func projectiveToAffine(in *edwards25519.ProjectiveGroupElement) (*big.Int, *big.Int) {
	var x, y, zinv edwards25519.FieldElement
	var bigX, bigY = new(big.Int), new(big.Int)

	edwards25519.FeInvert(&zinv, &in.Z)
	edwards25519.FeMul(&x, &in.X, &zinv)
	edwards25519.FeMul(&y, &in.Y, &zinv)

	feToBig(bigX, &x)
	feToBig(bigY, &y)

	return bigX, bigY
}

func feFromBig(h *edwards25519.FieldElement, in *big.Int) {
	tmp := new(big.Int).Mod(in, ed25519.P)
	tmpBytes := tmp.Bytes()
	var buf, reverse [32]byte
	copy(buf[32-len(tmpBytes):], tmpBytes)
	for i := 0; i < 32; i++ {
		reverse[i] = buf[31-i]
	}
	edwards25519.FeFromBytes(h, &reverse)
}

func feToBig(out *big.Int, h *edwards25519.FieldElement) {
	var buf, reverse [32]byte
	edwards25519.FeToBytes(&buf, h)
	for i := 0; i < 32; i++ {
		reverse[i] = buf[31-i]
	}
	out.SetBytes(reverse[:])
	out.Mod(out, ed25519.P)
}
