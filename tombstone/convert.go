package tombstone

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	tombstone "github.com/TrueCloudLab/frostfs-api-go/v2/tombstone/grpc"
)

func (s *Tombstone) ToGRPCMessage() grpc.Message {
	var m *tombstone.Tombstone

	if s != nil {
		m = new(tombstone.Tombstone)

		m.SetMembers(refs.ObjectIDListToGRPCMessage(s.members))
		m.SetExpirationEpoch(s.exp)
		m.SetSplitId(s.splitID)
	}

	return m
}

func (s *Tombstone) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*tombstone.Tombstone)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	s.members, err = refs.ObjectIDListFromGRPCMessage(v.GetMembers())
	if err != nil {
		return err
	}

	s.exp = v.GetExpirationEpoch()
	s.splitID = v.GetSplitId()

	return nil
}
