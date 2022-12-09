package lock

import refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"

// SetMembers sets `members` field.
func (x *Lock) SetMembers(ids []*refs.ObjectID) {
	x.Members = ids
}
