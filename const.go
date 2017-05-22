// Copyright (c) 2017 George Tankersley. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519

import (
	"math/big"

	"github.com/gtank/ed25519/internal/edwards25519"
)

var (
	// d2 is 2*d, a curve-specific constant used in our addition formula.
	d2 = edwards25519.FieldElement{
		-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199,
	}

	// the number 2 as a field element
	feTwo = edwards25519.FieldElement{
		2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)
