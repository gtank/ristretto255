package ristretto255

import (
	"encoding/hex"
	"testing"

	"github.com/gtank/ristretto255/internal/edwards25519"
	"github.com/gtank/ristretto255/internal/radix51"
)

func assertFeEqual(value, expect *radix51.FieldElement) {
	if value.Equal(expect) == 1 {
		return
	} else {
		panic("failed equality assertion")
	}
}

type sqrtRatioTest struct {
	u, v     *radix51.FieldElement
	sqrt     *radix51.FieldElement
	choice   int
	negative int
}

// These tests can be found in curve25519-dalek's 'field.rs'
func TestSqrtRatioM1(t *testing.T) {
	var (
		zero, one = radix51.Zero, radix51.One

		// Two is nonsquare in our field, 4 is square
		two  = new(radix51.FieldElement).Add(one, one)
		four = new(radix51.FieldElement).Add(two, two)

		// 2*i
		twoTimesSqrtM1 = new(radix51.FieldElement).Mul(two, sqrtM1)

		sqrt2i = fieldElementFromDecimal(
			"38214883241950591754978413199355411911188925816896391856984770930832735035196")

		invSqrt4 = fieldElementFromDecimal(
			"28948022309329048855892746252171976963317496166410141009864396001978282409974")
	)

	// Check the construction of those magic numbers.
	assertFeEqual(new(radix51.FieldElement).Mul(sqrt2i, sqrt2i), twoTimesSqrtM1)
	assertFeEqual(new(radix51.FieldElement).Mul(new(radix51.FieldElement).Square(invSqrt4), four), one)

	var tests = []sqrtRatioTest{
		{u: zero, v: zero, sqrt: zero, choice: 1, negative: 0},    // 0
		{u: one, v: zero, sqrt: zero, choice: 0, negative: 0},     // 1
		{u: two, v: one, sqrt: sqrt2i, choice: 0, negative: 0},    // 2
		{u: four, v: one, sqrt: two, choice: 1, negative: 0},      // 3
		{u: one, v: four, sqrt: invSqrt4, choice: 1, negative: 0}, // 4
	}

	for idx, tt := range tests {
		sqrt := new(radix51.FieldElement)
		choice := feSqrtRatio(sqrt, tt.u, tt.v)
		if choice != tt.choice || sqrt.Equal(tt.sqrt) != 1 || sqrt.IsNegative() != tt.negative {
			t.Errorf("Failed test %d", idx)
			t.Logf("Got {u: %v, v: %v, sqrt: %v, choice: %d, neg: %d}", tt.u, tt.v, sqrt, choice, sqrt.IsNegative())
		}
	}
}

func TestRistrettoBasepointDecode(t *testing.T) {
	var (
		// The encoding of Ristretto element that can be represented internally by the Curve25519 base point.
		compressedRistrettoBasepoint, _ = hex.DecodeString("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76")

		// The representative Ristretto basepoint in extended coordinates.
		ristrettoBasepoint = Element{r: edwards25519.ExtendedGroupElement{
			X: radix51.FieldElement([5]uint64{426475514619346, 2063872706840040, 14628272888959, 107677749330612, 288339085807592}),
			Y: radix51.FieldElement([5]uint64{1934594822876571, 2049809580636559, 1991994783322914, 1758681962032007, 380046701118659}),
			Z: radix51.FieldElement([5]uint64{1, 0, 0, 0, 0}),
			T: radix51.FieldElement([5]uint64{410445769351754, 2235400917701188, 1495825632738689, 1351628537510093, 430502003771208}),
		}}
	)

	decodedBasepoint := &Element{}
	err := decodedBasepoint.Decode(compressedRistrettoBasepoint)
	if err != nil {
		t.Fatal(err)
	}

	if decodedBasepoint.Equal(&ristrettoBasepoint) != 1 {
		t.Error("decode succeeded, but got wrong point")
	}
}
