// Package ed25519 implements an elliptic.Curve interface on top of the twisted
// Edwards curve -x^2 + y^2 = 1 + -(121665/121666)*x^2*y^2. This is better
// known as the Edwards curve equivalent to curve25519, and is the curve used
// by the Ed25519 signature scheme.
//
// Because of the Curve interface, this package takes input in affine (x,y)
// pairs instead of the more standard compressed Edwards y.
package ed25519
