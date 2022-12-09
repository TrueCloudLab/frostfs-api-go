package tombstone

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// SetExpirationEpoch sets number of tombstone expiration epoch.
func (x *Tombstone) SetExpirationEpoch(v uint64) {
	x.ExpirationEpoch = v
}

// SetSplitId sets identifier of split object hierarchy.
func (x *Tombstone) SetSplitId(v []byte) {
	x.SplitId = v
}

// SetMembers sets list of objects to be deleted.
func (x *Tombstone) SetMembers(v []*refs.ObjectID) {
	x.Members = v
}
