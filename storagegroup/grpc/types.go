package storagegroup

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// SetValidationDataSize sets the total size of the payloads of the storage group.
func (m *StorageGroup) SetValidationDataSize(v uint64) {
	m.ValidationDataSize = v
}

// SetValidationHash sets total homomorphic hash of the storage group payloads.
func (m *StorageGroup) SetValidationHash(v *refs.Checksum) {
	m.ValidationHash = v
}

// SetExpirationEpoch sets number of the last epoch of the storage group lifetime.
//
// Deprecated: do not use, `expiration_epoch` field is deprecated in protocol.
func (m *StorageGroup) SetExpirationEpoch(v uint64) {
	m.ExpirationEpoch = v
}

// SetMembers sets list of the identifiers of the storage group members.
func (m *StorageGroup) SetMembers(v []*refs.ObjectID) {
	m.Members = v
}
