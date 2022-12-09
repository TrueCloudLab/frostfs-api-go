package storagegrouptest

import (
	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/storagegroup"
)

func GenerateStorageGroup(empty bool) *storagegroup.StorageGroup {
	m := new(storagegroup.StorageGroup)

	if !empty {
		m.SetValidationDataSize(44)
		//nolint:staticcheck
		m.SetExpirationEpoch(55)
		m.SetMembers(refstest.GenerateObjectIDs(false))
	}

	m.SetValidationHash(refstest.GenerateChecksum(empty))

	return m
}
