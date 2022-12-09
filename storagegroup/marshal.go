package storagegroup

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	storagegroup "github.com/TrueCloudLab/frostfs-api-go/v2/storagegroup/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	sizeField       = 1
	hashField       = 2
	expirationField = 3
	objectIDsField  = 4
)

// StableMarshal marshals unified storage group structure in a protobuf
// compatible way without field order shuffle.
func (s *StorageGroup) StableMarshal(buf []byte) []byte {
	if s == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, s.StableSize())
	}

	var offset int

	offset += proto.UInt64Marshal(sizeField, buf[offset:], s.size)
	offset += proto.NestedStructureMarshal(hashField, buf[offset:], s.hash)
	offset += proto.UInt64Marshal(expirationField, buf[offset:], s.exp)
	refs.ObjectIDNestedListMarshal(objectIDsField, buf[offset:], s.members)

	return buf
}

// StableSize of storage group structure marshalled by StableMarshal function.
func (s *StorageGroup) StableSize() (size int) {
	if s == nil {
		return 0
	}

	size += proto.UInt64Size(sizeField, s.size)
	size += proto.NestedStructureSize(hashField, s.hash)
	size += proto.UInt64Size(expirationField, s.exp)
	size += refs.ObjectIDNestedListSize(objectIDsField, s.members)

	return size
}

func (s *StorageGroup) Unmarshal(data []byte) error {
	return message.Unmarshal(s, data, new(storagegroup.StorageGroup))
}
