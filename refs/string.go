package refs

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// String returns string representation of ChecksumType.
func (t ChecksumType) String() string {
	return ChecksumTypeToGRPC(t).String()
}

// FromString parses ChecksumType from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (t *ChecksumType) FromString(s string) bool {
	var g refs.ChecksumType

	ok := g.FromString(s)

	if ok {
		*t = ChecksumTypeFromGRPC(g)
	}

	return ok
}

// String returns string representation of SignatureScheme.
func (t SignatureScheme) String() string {
	return refs.SignatureScheme(t).String()
}

// FromString parses SignatureScheme from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (t *SignatureScheme) FromString(s string) bool {
	var g refs.SignatureScheme

	ok := g.FromString(s)

	if ok {
		*t = SignatureScheme(g)
	}

	return ok
}
