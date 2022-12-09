package object

import (
	object "github.com/TrueCloudLab/frostfs-api-go/v2/object/grpc"
)

// String returns string representation of Type.
func (t Type) String() string {
	return TypeToGRPCField(t).String()
}

// FromString parses Type from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (t *Type) FromString(s string) bool {
	var g object.ObjectType

	ok := g.FromString(s)

	if ok {
		*t = TypeFromGRPCField(g)
	}

	return ok
}

// TypeFromString converts string to Type.
//
// Deprecated: use FromString method.
func TypeFromString(s string) (t Type) {
	t.FromString(s)
	return
}

// String returns string representation of MatchType.
func (t MatchType) String() string {
	return MatchTypeToGRPCField(t).String()
}

// FromString parses MatchType from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (t *MatchType) FromString(s string) bool {
	var g object.MatchType

	ok := g.FromString(s)

	if ok {
		*t = MatchTypeFromGRPCField(g)
	}

	return ok
}
