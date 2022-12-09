package tombstone

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	tombstone "github.com/TrueCloudLab/frostfs-api-go/v2/tombstone/grpc"
)

func (s *Tombstone) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(s)
}

func (s *Tombstone) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(s, data, new(tombstone.Tombstone))
}
