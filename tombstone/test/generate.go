package tombstonetest

import (
	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/tombstone"
)

func GenerateTombstone(empty bool) *tombstone.Tombstone {
	m := new(tombstone.Tombstone)

	if !empty {
		m.SetExpirationEpoch(89)
		m.SetSplitID([]byte{3, 2, 1})
		m.SetMembers(refstest.GenerateObjectIDs(false))
	}

	return m
}
