package session

import (
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// String returns string representation of ObjectSessionVerb.
func (x ObjectSessionVerb) String() string {
	return ObjectSessionVerbToGRPCField(x).String()
}

// FromString parses ObjectSessionVerb from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *ObjectSessionVerb) FromString(s string) bool {
	var g session.ObjectSessionContext_Verb

	ok := g.FromString(s)

	if ok {
		*x = ObjectSessionVerbFromGRPCField(g)
	}

	return ok
}

// String returns string representation of ContainerSessionVerb.
func (x ContainerSessionVerb) String() string {
	return ContainerSessionVerbToGRPCField(x).String()
}

// FromString parses ContainerSessionVerb from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *ContainerSessionVerb) FromString(s string) bool {
	var g session.ContainerSessionContext_Verb

	ok := g.FromString(s)

	if ok {
		*x = ContainerSessionVerbFromGRPCField(g)
	}

	return ok
}
