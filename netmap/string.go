package netmap

import (
	netmap "github.com/TrueCloudLab/frostfs-api-go/v2/netmap/grpc"
)

// String returns string representation of Clause.
func (x Clause) String() string {
	return ClauseToGRPCMessage(x).String()
}

// FromString parses Clause from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *Clause) FromString(s string) bool {
	var g netmap.Clause

	ok := g.FromString(s)

	if ok {
		*x = ClauseFromGRPCMessage(g)
	}

	return ok
}

// String returns string representation of Operation.
func (x Operation) String() string {
	return OperationToGRPCMessage(x).String()
}

// FromString parses Operation from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *Operation) FromString(s string) bool {
	var g netmap.Operation

	ok := g.FromString(s)

	if ok {
		*x = OperationFromGRPCMessage(g)
	}

	return ok
}

// String returns string representation of NodeState.
func (x NodeState) String() string {
	return NodeStateToGRPCMessage(x).String()
}

// FromString parses NodeState from a string representation.
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *NodeState) FromString(s string) bool {
	var g netmap.NodeInfo_State

	ok := g.FromString(s)

	if ok {
		*x = NodeStateFromRPCMessage(g)
	}

	return ok
}
