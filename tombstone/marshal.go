package tombstone

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	tombstone "github.com/TrueCloudLab/frostfs-api-go/v2/tombstone/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	expFNum     = 1
	splitIDFNum = 2
	membersFNum = 3
)

// StableMarshal marshals unified tombstone message in a protobuf
// compatible way without field order shuffle.
func (s *Tombstone) StableMarshal(buf []byte) []byte {
	if s == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, s.StableSize())
	}

	var offset int

	offset += proto.UInt64Marshal(expFNum, buf[offset:], s.exp)
	offset += proto.BytesMarshal(splitIDFNum, buf[offset:], s.splitID)

	for i := range s.members {
		offset += proto.NestedStructureMarshal(membersFNum, buf[offset:], &s.members[i])
	}

	return buf
}

// StableSize returns size of tombstone message marshalled by StableMarshal function.
func (s *Tombstone) StableSize() (size int) {
	if s == nil {
		return 0
	}

	size += proto.UInt64Size(expFNum, s.exp)
	size += proto.BytesSize(splitIDFNum, s.splitID)
	for i := range s.members {
		size += proto.NestedStructureSize(membersFNum, &s.members[i])
	}

	return size
}

// Unmarshal unmarshal tombstone message from its binary representation.
func (s *Tombstone) Unmarshal(data []byte) error {
	return message.Unmarshal(s, data, new(tombstone.Tombstone))
}
