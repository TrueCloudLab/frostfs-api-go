package acl

import (
	acl "github.com/TrueCloudLab/frostfs-api-go/v2/acl/grpc"
)

// String returns string representation of Action.
func (x Action) String() string {
	return ActionToGRPCField(x).String()
}

// FromString parses Action from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *Action) FromString(s string) bool {
	var g acl.Action

	ok := g.FromString(s)

	if ok {
		*x = ActionFromGRPCField(g)
	}

	return ok
}

// String returns string representation of Role.
func (x Role) String() string {
	return RoleToGRPCField(x).String()
}

// FromString parses Role from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *Role) FromString(s string) bool {
	var g acl.Role

	ok := g.FromString(s)

	if ok {
		*x = RoleFromGRPCField(g)
	}

	return ok
}

// String returns string representation of Operation.
func (x Operation) String() string {
	return OperationToGRPCField(x).String()
}

// FromString parses Operation from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *Operation) FromString(s string) bool {
	var g acl.Operation

	ok := g.FromString(s)

	if ok {
		*x = OperationFromGRPCField(g)
	}

	return ok
}

// String returns string representation of MatchType.
func (x MatchType) String() string {
	return MatchTypeToGRPCField(x).String()
}

// FromString parses MatchType from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *MatchType) FromString(s string) bool {
	var g acl.MatchType

	ok := g.FromString(s)

	if ok {
		*x = MatchTypeFromGRPCField(g)
	}

	return ok
}

// String returns string representation of HeaderType.
func (x HeaderType) String() string {
	return HeaderTypeToGRPCField(x).String()
}

// FromString parses HeaderType from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *HeaderType) FromString(s string) bool {
	var g acl.HeaderType

	ok := g.FromString(s)

	if ok {
		*x = HeaderTypeFromGRPCField(g)
	}

	return ok
}
