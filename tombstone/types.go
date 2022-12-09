package tombstone

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
)

// Tombstone is a unified structure of Tombstone
// message from proto definition.
type Tombstone struct {
	exp uint64

	splitID []byte

	members []refs.ObjectID
}

// GetExpirationEpoch returns number of tombstone expiration epoch.
func (s *Tombstone) GetExpirationEpoch() uint64 {
	if s != nil {
		return s.exp
	}

	return 0
}

// SetExpirationEpoch sets number of tombstone expiration epoch.
func (s *Tombstone) SetExpirationEpoch(v uint64) {
	s.exp = v
}

// GetSplitID returns identifier of split object hierarchy.
func (s *Tombstone) GetSplitID() []byte {
	if s != nil {
		return s.splitID
	}

	return nil
}

// SetSplitID sets identifier of split object hierarchy.
func (s *Tombstone) SetSplitID(v []byte) {
	s.splitID = v
}

// GetMembers returns list of objects to be deleted.
func (s *Tombstone) GetMembers() []refs.ObjectID {
	if s != nil {
		return s.members
	}

	return nil
}

// SetMembers sets list of objects to be deleted.
func (s *Tombstone) SetMembers(v []refs.ObjectID) {
	s.members = v
}
