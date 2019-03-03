package ristretto255

import (
	"testing"
)

func TestRistrettoBasepointDecode(t *testing.T) {
	extendedBasepoint := &Element{}
	err := extendedBasepoint.Decode(encodedBasepoint)
	if err != nil {
		t.Fatal(err)
	}
}
