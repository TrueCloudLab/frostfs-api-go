package storagegroup

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	sg "github.com/TrueCloudLab/frostfs-api-go/v2/storagegroup/grpc"
)

func (s *StorageGroup) ToGRPCMessage() grpc.Message {
	m := new(sg.StorageGroup)

	if s != nil {
		m = new(sg.StorageGroup)

		m.SetMembers(refs.ObjectIDListToGRPCMessage(s.members))
		//nolint:staticcheck
		m.SetExpirationEpoch(s.exp)
		m.SetValidationDataSize(s.size)
		m.SetValidationHash(s.hash.ToGRPCMessage().(*refsGRPC.Checksum))
	}

	return m
}

func (s *StorageGroup) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*sg.StorageGroup)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	hash := v.GetValidationHash()
	if hash == nil {
		s.hash = nil
	} else {
		if s.hash == nil {
			s.hash = new(refs.Checksum)
		}

		err = s.hash.FromGRPCMessage(hash)
		if err != nil {
			return err
		}
	}

	s.members, err = refs.ObjectIDListFromGRPCMessage(v.GetMembers())
	if err != nil {
		return err
	}

	//nolint:staticcheck
	s.exp = v.GetExpirationEpoch()
	s.size = v.GetValidationDataSize()

	return nil
}
