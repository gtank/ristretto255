package ristretto255

import (
	"bytes"
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

func TestRistrettoBasepointRoundTrip(t *testing.T) {
	decodedBasepoint := &Element{}
	err := decodedBasepoint.Decode(compressedRistrettoBasepoint)
	if err != nil {
		t.Fatal(err)
	}

	if decodedBasepoint.Equal(&ristrettoBasepoint) != 1 {
		t.Error("decode succeeded, but got wrong point")
	}

	roundtripBasepoint := decodedBasepoint.Encode(nil)
	if !bytes.Equal(compressedRistrettoBasepoint, roundtripBasepoint) {
		t.Error("decode<>encode roundtrip produced different results")
	}

	encodedBasepoint := ristrettoBasepoint.Encode(nil)
	if !bytes.Equal(compressedRistrettoBasepoint, encodedBasepoint) {
		t.Error("point encode produced different results")
	}
}

func TestRistrettoRandomRoundtrip(t *testing.T) {
	// TODO quickcheck
}

func TestRistrettoSmallMultiplesTestVectors(t *testing.T) {
	var testVectors = [16]string{
		// This is the identity point
		"0000000000000000000000000000000000000000000000000000000000000000",
		// This is the basepoint
		"e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
		// These are small multiples of the basepoint
		"6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
		"94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
		"da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
		"e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
		"f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
		"44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
		"903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
		"02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
		"20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
		"bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
		"e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
		"aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
		"46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
		"e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
	}

	basepointMultiple := Element{}
	basepointMultiple.Zero()

	for i := range testVectors {
		// Grab the bytes of the encoding
		encoding, err := hex.DecodeString(testVectors[i])
		if err != nil {
			t.Fatalf("#%d: bad hex encoding in test vector: %v", i, err)
		}

		// Decode the test vector to a ristretto255 element
		decodedPoint := Element{}
		err = decodedPoint.Decode(encoding)
		if err != nil {
			t.Error("Could not decode test vector")
		}
		// Re-encode and check round trips
		roundtripEncoding := decodedPoint.Encode(nil)
		if !bytes.Equal(encoding, roundtripEncoding) {
			t.Errorf("decode<>encode roundtrip failed on test vector %d", i)
		}

		// Check that the test vector encodes i * B
		if basepointMultiple.Equal(&decodedPoint) != 1 {
			t.Errorf("decoded small multiple %d * B is not %d * B", i, i)
		}
		// Ensure basepointMultiple = i * B in the next iteration
		basepointMultiple.Add(&basepointMultiple, &ristrettoBasepoint)
	}
}
