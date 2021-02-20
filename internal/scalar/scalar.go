// Copyright 2016 The Go Authors. All rights reserved.
// Copyright 2019 Henry de Valence. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scalar implements the ristretto255 scalar group.
package scalar

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	mathrand "math/rand"
	"reflect"
)

// A Scalar is an integer modulo l = 2^252 + 27742317777372353535851937790883648493.
// Internally, this implementation keeps the scalar in the Montgomery domain.
type Scalar [4]uint64

var (
	// 1 in the Montgomery domain
	scOne = Scalar([4]uint64{0xd6ec31748d98951d, 0xc6ef5bf4737dcf70, 0xfffffffffffffffe, 0xfffffffffffffff})
)

// Add sets s = x + y mod l and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	fiat_sc255_add((*[4]uint64)(s), (*[4]uint64)(x), (*[4]uint64)(y))
	return s
}

// Sub sets s = x - y mod l and returns s.
func (s *Scalar) Sub(x, y *Scalar) *Scalar {
	fiat_sc255_sub((*[4]uint64)(s), (*[4]uint64)(x), (*[4]uint64)(y))
	return s
}

// Neg sets s = -x mod l and returns s.
func (s *Scalar) Neg(x *Scalar) *Scalar {
	fiat_sc255_opp((*[4]uint64)(s), (*[4]uint64)(x))
	return s
}

// Mul sets s = x * y mod l and returns s.
func (s *Scalar) Mul(x, y *Scalar) *Scalar {
	fiat_sc255_mul((*[4]uint64)(s), (*[4]uint64)(x), (*[4]uint64)(y))
	return s
}

// FromUniformBytes sets s to an uniformly distributed value given 64 uniformly
// distributed random bytes.
func (s *Scalar) FromUniformBytes(x []byte) *Scalar {
	if len(x) != 64 {
		panic("scalar: invalid uniform input length")
	}

	var wideBytes [64]byte
	copy(wideBytes[:], x[:])

	// TODO: scReduce is deprecated but retained here for consistent behavior
	var reduced [32]byte
	scReduce(&reduced, &wideBytes)

	fiat_sc255_from_bytes((*[4]uint64)(s), &reduced)
	fiat_sc255_to_montgomery((*[4]uint64)(s), (*[4]uint64)(s))

	return s
}

// FromCanonicalBytes sets s = x, where x is a 32 bytes little-endian encoding
// of s. If x is not a canonical encoding of s, FromCanonicalBytes returns an
// error and the receiver is unchanged.
func (s *Scalar) FromCanonicalBytes(x []byte) error {
	if len(x) != 32 {
		panic("scalar: invalid scalar length")
	}

	if !scMinimal(x) {
		return errors.New("invalid scalar encoding")
	}

	var b [32]byte
	var in [4]uint64

	copy(b[:], x)

	fiat_sc255_from_bytes(&in, &b)
	fiat_sc255_to_montgomery((*[4]uint64)(s), &in)
	return nil
}

// Bytes appends a 32 bytes little-endian encoding of s to b.
func (s *Scalar) Bytes(b []byte) []byte {
	var reduced [4]uint64
	var repr [32]byte

	fiat_sc255_from_montgomery(&reduced, (*[4]uint64)(s))
	fiat_sc255_to_bytes(&repr, &reduced)

	res, out := sliceForAppend(b, 32)
	copy(out, repr[:])

	return res
}

// Equal returns 1 if s and t are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
	var ss, st [32]byte
	t.Bytes(st[:0])
	s.Bytes(ss[:0])
	return subtle.ConstantTimeCompare(ss[:], st[:])
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func load3(in []byte) int64 {
	r := int64(in[0])
	r |= int64(in[1]) << 8
	r |= int64(in[2]) << 16
	return r
}

func load4(in []byte) int64 {
	r := int64(in[0])
	r |= int64(in[1]) << 8
	r |= int64(in[2]) << 16
	r |= int64(in[3]) << 24
	return r
}

// Input:
//   s[0]+256*s[1]+...+256^63*s[63] = s
//
// Output:
//   s[0]+256*s[1]+...+256^31*s[31] = s mod l
//   where l = 2^252 + 27742317777372353535851937790883648493.
func scReduce(out *[32]byte, s *[64]byte) {
	s0 := 2097151 & load3(s[:])
	s1 := 2097151 & (load4(s[2:]) >> 5)
	s2 := 2097151 & (load3(s[5:]) >> 2)
	s3 := 2097151 & (load4(s[7:]) >> 7)
	s4 := 2097151 & (load4(s[10:]) >> 4)
	s5 := 2097151 & (load3(s[13:]) >> 1)
	s6 := 2097151 & (load4(s[15:]) >> 6)
	s7 := 2097151 & (load3(s[18:]) >> 3)
	s8 := 2097151 & load3(s[21:])
	s9 := 2097151 & (load4(s[23:]) >> 5)
	s10 := 2097151 & (load3(s[26:]) >> 2)
	s11 := 2097151 & (load4(s[28:]) >> 7)
	s12 := 2097151 & (load4(s[31:]) >> 4)
	s13 := 2097151 & (load3(s[34:]) >> 1)
	s14 := 2097151 & (load4(s[36:]) >> 6)
	s15 := 2097151 & (load3(s[39:]) >> 3)
	s16 := 2097151 & load3(s[42:])
	s17 := 2097151 & (load4(s[44:]) >> 5)
	s18 := 2097151 & (load3(s[47:]) >> 2)
	s19 := 2097151 & (load4(s[49:]) >> 7)
	s20 := 2097151 & (load4(s[52:]) >> 4)
	s21 := 2097151 & (load3(s[55:]) >> 1)
	s22 := 2097151 & (load4(s[57:]) >> 6)
	s23 := (load4(s[60:]) >> 3)

	s11 += s23 * 666643
	s12 += s23 * 470296
	s13 += s23 * 654183
	s14 -= s23 * 997805
	s15 += s23 * 136657
	s16 -= s23 * 683901
	s23 = 0

	s10 += s22 * 666643
	s11 += s22 * 470296
	s12 += s22 * 654183
	s13 -= s22 * 997805
	s14 += s22 * 136657
	s15 -= s22 * 683901
	s22 = 0

	s9 += s21 * 666643
	s10 += s21 * 470296
	s11 += s21 * 654183
	s12 -= s21 * 997805
	s13 += s21 * 136657
	s14 -= s21 * 683901
	s21 = 0

	s8 += s20 * 666643
	s9 += s20 * 470296
	s10 += s20 * 654183
	s11 -= s20 * 997805
	s12 += s20 * 136657
	s13 -= s20 * 683901
	s20 = 0

	s7 += s19 * 666643
	s8 += s19 * 470296
	s9 += s19 * 654183
	s10 -= s19 * 997805
	s11 += s19 * 136657
	s12 -= s19 * 683901
	s19 = 0

	s6 += s18 * 666643
	s7 += s18 * 470296
	s8 += s18 * 654183
	s9 -= s18 * 997805
	s10 += s18 * 136657
	s11 -= s18 * 683901
	s18 = 0

	var carry [17]int64

	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[12] = (s12 + (1 << 20)) >> 21
	s13 += carry[12]
	s12 -= carry[12] << 21
	carry[14] = (s14 + (1 << 20)) >> 21
	s15 += carry[14]
	s14 -= carry[14] << 21
	carry[16] = (s16 + (1 << 20)) >> 21
	s17 += carry[16]
	s16 -= carry[16] << 21

	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21
	carry[13] = (s13 + (1 << 20)) >> 21
	s14 += carry[13]
	s13 -= carry[13] << 21
	carry[15] = (s15 + (1 << 20)) >> 21
	s16 += carry[15]
	s15 -= carry[15] << 21

	s5 += s17 * 666643
	s6 += s17 * 470296
	s7 += s17 * 654183
	s8 -= s17 * 997805
	s9 += s17 * 136657
	s10 -= s17 * 683901
	s17 = 0

	s4 += s16 * 666643
	s5 += s16 * 470296
	s6 += s16 * 654183
	s7 -= s16 * 997805
	s8 += s16 * 136657
	s9 -= s16 * 683901
	s16 = 0

	s3 += s15 * 666643
	s4 += s15 * 470296
	s5 += s15 * 654183
	s6 -= s15 * 997805
	s7 += s15 * 136657
	s8 -= s15 * 683901
	s15 = 0

	s2 += s14 * 666643
	s3 += s14 * 470296
	s4 += s14 * 654183
	s5 -= s14 * 997805
	s6 += s14 * 136657
	s7 -= s14 * 683901
	s14 = 0

	s1 += s13 * 666643
	s2 += s13 * 470296
	s3 += s13 * 654183
	s4 -= s13 * 997805
	s5 += s13 * 136657
	s6 -= s13 * 683901
	s13 = 0

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = (s0 + (1 << 20)) >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[2] = (s2 + (1 << 20)) >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[4] = (s4 + (1 << 20)) >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[6] = (s6 + (1 << 20)) >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[8] = (s8 + (1 << 20)) >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[10] = (s10 + (1 << 20)) >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	carry[1] = (s1 + (1 << 20)) >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[3] = (s3 + (1 << 20)) >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[5] = (s5 + (1 << 20)) >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[7] = (s7 + (1 << 20)) >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[9] = (s9 + (1 << 20)) >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[11] = (s11 + (1 << 20)) >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21
	carry[11] = s11 >> 21
	s12 += carry[11]
	s11 -= carry[11] << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry[0] = s0 >> 21
	s1 += carry[0]
	s0 -= carry[0] << 21
	carry[1] = s1 >> 21
	s2 += carry[1]
	s1 -= carry[1] << 21
	carry[2] = s2 >> 21
	s3 += carry[2]
	s2 -= carry[2] << 21
	carry[3] = s3 >> 21
	s4 += carry[3]
	s3 -= carry[3] << 21
	carry[4] = s4 >> 21
	s5 += carry[4]
	s4 -= carry[4] << 21
	carry[5] = s5 >> 21
	s6 += carry[5]
	s5 -= carry[5] << 21
	carry[6] = s6 >> 21
	s7 += carry[6]
	s6 -= carry[6] << 21
	carry[7] = s7 >> 21
	s8 += carry[7]
	s7 -= carry[7] << 21
	carry[8] = s8 >> 21
	s9 += carry[8]
	s8 -= carry[8] << 21
	carry[9] = s9 >> 21
	s10 += carry[9]
	s9 -= carry[9] << 21
	carry[10] = s10 >> 21
	s11 += carry[10]
	s10 -= carry[10] << 21

	out[0] = byte(s0 >> 0)
	out[1] = byte(s0 >> 8)
	out[2] = byte((s0 >> 16) | (s1 << 5))
	out[3] = byte(s1 >> 3)
	out[4] = byte(s1 >> 11)
	out[5] = byte((s1 >> 19) | (s2 << 2))
	out[6] = byte(s2 >> 6)
	out[7] = byte((s2 >> 14) | (s3 << 7))
	out[8] = byte(s3 >> 1)
	out[9] = byte(s3 >> 9)
	out[10] = byte((s3 >> 17) | (s4 << 4))
	out[11] = byte(s4 >> 4)
	out[12] = byte(s4 >> 12)
	out[13] = byte((s4 >> 20) | (s5 << 1))
	out[14] = byte(s5 >> 7)
	out[15] = byte((s5 >> 15) | (s6 << 6))
	out[16] = byte(s6 >> 2)
	out[17] = byte(s6 >> 10)
	out[18] = byte((s6 >> 18) | (s7 << 3))
	out[19] = byte(s7 >> 5)
	out[20] = byte(s7 >> 13)
	out[21] = byte(s8 >> 0)
	out[22] = byte(s8 >> 8)
	out[23] = byte((s8 >> 16) | (s9 << 5))
	out[24] = byte(s9 >> 3)
	out[25] = byte(s9 >> 11)
	out[26] = byte((s9 >> 19) | (s10 << 2))
	out[27] = byte(s10 >> 6)
	out[28] = byte((s10 >> 14) | (s11 << 7))
	out[29] = byte(s11 >> 1)
	out[30] = byte(s11 >> 9)
	out[31] = byte(s11 >> 17)
}

// order is the order of Curve25519 in little-endian form.
var order = [4]uint64{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

// scMinimal returns true if the given little-endian byte
// representation of a scalar NOT in the Montgomery domain
// is less than the order of the group.
func scMinimal(sc []byte) bool {
	if len(sc) != 32 {
		return false
	}

	for i := 3; ; i-- {
		v := binary.LittleEndian.Uint64(sc[i*8:])
		if v > order[i] {
			return false
		} else if v < order[i] {
			break
		} else if i == 0 {
			return false
		}
	}

	return true
}

// NonAdjacentForm computes a width-w non-adjacent form for this scalar.
func (s *Scalar) NonAdjacentForm(w uint) [256]int8 {
	byteRepr := s.Bytes(nil)

	// This implementation is adapted from the one
	// in curve25519-dalek and is documented there:
	// https://github.com/dalek-cryptography/curve25519-dalek/blob/f630041af28e9a405255f98a8a93adca18e4315b/src/scalar.rs#L800-L871
	if byteRepr[31] > 127 {
		panic("scalar has high bit set illegally")
	}
	if w < 2 {
		panic("w must be at least 2 by the definition of NAF")
	} else if w > 8 {
		panic("NAF digits must fit in int8")
	}

	var naf [256]int8
	var digits [5]uint64

	for i := 0; i < 4; i++ {
		digits[i] = binary.LittleEndian.Uint64(byteRepr[i*8:])
	}

	width := uint64(1 << w)
	windowMask := uint64(width - 1)

	pos := uint(0)
	carry := uint64(0)
	for pos < 256 {
		indexU64 := pos / 64
		indexBit := pos % 64
		var bitBuf uint64
		if indexBit < 64-w {
			// This window's bits are contained in a single u64
			bitBuf = digits[indexU64] >> indexBit
		} else {
			// Combine the current 64 bits with bits from the next 64
			bitBuf = (digits[indexU64] >> indexBit) | (digits[1+indexU64] << (64 - indexBit))
		}

		// Add carry into the current window
		window := carry + (bitBuf & windowMask)

		if window&1 == 0 {
			// If the window value is even, preserve the carry and continue.
			// Why is the carry preserved?
			// If carry == 0 and window & 1 == 0,
			//    then the next carry should be 0
			// If carry == 1 and window & 1 == 0,
			//    then bit_buf & 1 == 1 so the next carry should be 1
			pos += 1
			continue
		}

		if window < width/2 {
			carry = 0
			naf[pos] = int8(window)
		} else {
			carry = 1
			naf[pos] = int8(window) - int8(width)
		}

		pos += w
	}
	return naf
}

func (s *Scalar) SignedRadix16() [64]int8 {
	byteRepr := s.Bytes(nil)

	if byteRepr[31] > 127 {
		panic("scalar has high bit set illegally")
	}

	var digits [64]int8

	// Compute unsigned radix-16 digits:
	for i := 0; i < 32; i++ {
		digits[2*i] = int8(byteRepr[i] & 15)
		digits[2*i+1] = int8((byteRepr[i] >> 4) & 15)
	}

	// Recenter coefficients:
	for i := 0; i < 63; i++ {
		carry := (digits[i] + 8) >> 4
		digits[i] -= carry << 4
		digits[i+1] += carry
	}

	return digits
}

// Given k > 0, set s = s**(2*i).
func (s *Scalar) pow2k(k int) {
	for i := 0; i < k; i++ {
		s.Mul(s, s)
	}
}

// Inv sets s to the inverse of a nonzero scalar v and returns s.
func (s *Scalar) Inv(t *Scalar) *Scalar {
	// Uses a hardcoded sliding window of width 4.
	var table [8]Scalar
	var tt Scalar
	tt.Mul(t, t)
	table[0] = *t
	for i := 0; i < 7; i++ {
		table[i+1].Mul(&table[i], &tt)
	}
	// Now table = [t**1, t**3, t**7, t**11, t**13, t**15]
	// so t**k = t[k/2] for odd k

	// To compute the sliding window digits, use the following Sage script:

	// sage: import itertools
	// sage: def sliding_window(w,k):
	// ....:     digits = []
	// ....:     while k > 0:
	// ....:         if k % 2 == 1:
	// ....:             kmod = k % (2**w)
	// ....:             digits.append(kmod)
	// ....:             k = k - kmod
	// ....:         else:
	// ....:             digits.append(0)
	// ....:         k = k // 2
	// ....:     return digits

	// Now we can compute s roughly as follows:

	// sage: s = 1
	// sage: for coeff in reversed(sliding_window(4,l-2)):
	// ....:     s = s*s
	// ....:     if coeff > 0 :
	// ....:         s = s*t**coeff

	// This works on one bit at a time, with many runs of zeros.
	// The digits can be collapsed into [(count, coeff)] as follows:

	// sage: [(len(list(group)),d) for d,group in itertools.groupby(sliding_window(4,l-2))]

	// Entries of the form (k, 0) turn into pow2k(k)
	// Entries of the form (1, coeff) turn into a squaring and then a table lookup.
	// We can fold the squaring into the previous pow2k(k) as pow2k(k+1).

	*s = table[1/2]
	s.pow2k(127 + 1)
	s.Mul(s, &table[1/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[9/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[11/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[13/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[15/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[7/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[15/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[5/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[1/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[15/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[15/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[7/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[3/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[11/2])
	s.pow2k(5 + 1)
	s.Mul(s, &table[11/2])
	s.pow2k(9 + 1)
	s.Mul(s, &table[9/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[3/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[3/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[3/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[9/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[7/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[3/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[13/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[7/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[9/2])
	s.pow2k(3 + 1)
	s.Mul(s, &table[15/2])
	s.pow2k(4 + 1)
	s.Mul(s, &table[11/2])

	return s
}

func generateScalar(mrand *mathrand.Rand) Scalar {
	var r [64]byte
	mrand.Read(r[:])
	s := (&Scalar{}).FromUniformBytes(r[:])
	return *s
}

// Generate generates an arbitrary valid Scalar for quickcheck tests.
// It is here because it needs to be visible for other packages (currently internal/edwards25519)
// that want scalars in their tests.
func (sc Scalar) Generate(mrand *mathrand.Rand, size int) reflect.Value {
	return reflect.ValueOf(generateScalar(mrand))
}
