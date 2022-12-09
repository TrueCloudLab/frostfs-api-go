package refs

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (o *OwnerID) ToGRPCMessage() grpc.Message {
	var m *refs.OwnerID

	if o != nil {
		m = new(refs.OwnerID)

		m.SetValue(o.val)
	}

	return m
}

func (o *OwnerID) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*refs.OwnerID)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	o.val = v.GetValue()

	return nil
}

func (c *ContainerID) ToGRPCMessage() grpc.Message {
	var m *refs.ContainerID

	if c != nil {
		m = new(refs.ContainerID)

		m.SetValue(c.val)
	}

	return m
}

func (c *ContainerID) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*refs.ContainerID)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	c.val = v.GetValue()

	return nil
}

func ContainerIDsToGRPCMessage(ids []ContainerID) (res []*refs.ContainerID) {
	if ids != nil {
		res = make([]*refs.ContainerID, 0, len(ids))

		for i := range ids {
			res = append(res, ids[i].ToGRPCMessage().(*refs.ContainerID))
		}
	}

	return
}

func ContainerIDsFromGRPCMessage(idsV2 []*refs.ContainerID) (res []ContainerID, err error) {
	if idsV2 != nil {
		res = make([]ContainerID, len(idsV2))

		for i := range idsV2 {
			if idsV2[i] != nil {
				err = res[i].FromGRPCMessage(idsV2[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (o *ObjectID) ToGRPCMessage() grpc.Message {
	var m *refs.ObjectID

	if o != nil {
		m = new(refs.ObjectID)

		m.SetValue(o.val)
	}

	return m
}

func (o *ObjectID) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*refs.ObjectID)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	o.val = v.GetValue()

	return nil
}

func ObjectIDListToGRPCMessage(ids []ObjectID) (res []*refs.ObjectID) {
	if ids != nil {
		res = make([]*refs.ObjectID, 0, len(ids))

		for i := range ids {
			res = append(res, ids[i].ToGRPCMessage().(*refs.ObjectID))
		}
	}

	return
}

func ObjectIDListFromGRPCMessage(idsV2 []*refs.ObjectID) (res []ObjectID, err error) {
	if idsV2 != nil {
		res = make([]ObjectID, len(idsV2))

		for i := range idsV2 {
			if idsV2[i] != nil {
				err = res[i].FromGRPCMessage(idsV2[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (a *Address) ToGRPCMessage() grpc.Message {
	var m *refs.Address

	if a != nil {
		m = new(refs.Address)

		m.SetContainerId(a.cid.ToGRPCMessage().(*refs.ContainerID))
		m.SetObjectId(a.oid.ToGRPCMessage().(*refs.ObjectID))
	}

	return m
}

func (a *Address) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*refs.Address)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	cid := v.GetContainerId()
	if cid == nil {
		a.cid = nil
	} else {
		if a.cid == nil {
			a.cid = new(ContainerID)
		}

		err = a.cid.FromGRPCMessage(cid)
		if err != nil {
			return err
		}
	}

	oid := v.GetObjectId()
	if oid == nil {
		a.oid = nil
	} else {
		if a.oid == nil {
			a.oid = new(ObjectID)
		}

		err = a.oid.FromGRPCMessage(oid)
	}

	return err
}

func ChecksumTypeToGRPC(t ChecksumType) refs.ChecksumType {
	return refs.ChecksumType(t)
}

func ChecksumTypeFromGRPC(t refs.ChecksumType) ChecksumType {
	return ChecksumType(t)
}

func (c *Checksum) ToGRPCMessage() grpc.Message {
	var m *refs.Checksum

	if c != nil {
		m = new(refs.Checksum)

		m.SetChecksumType(ChecksumTypeToGRPC(c.typ))
		m.SetSum(c.sum)
	}

	return m
}

func (c *Checksum) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*refs.Checksum)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	c.typ = ChecksumTypeFromGRPC(v.GetType())
	c.sum = v.GetSum()

	return nil
}

func (v *Version) ToGRPCMessage() grpc.Message {
	var m *refs.Version

	if v != nil {
		m = new(refs.Version)

		m.SetMajor(v.major)
		m.SetMinor(v.minor)
	}

	return m
}

func (v *Version) FromGRPCMessage(m grpc.Message) error {
	ver, ok := m.(*refs.Version)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	v.major = ver.GetMajor()
	v.minor = ver.GetMinor()

	return nil
}

func (s *Signature) ToGRPCMessage() grpc.Message {
	var m *refs.Signature

	if s != nil {
		m = new(refs.Signature)

		m.SetKey(s.key)
		m.SetSign(s.sign)
		m.SetScheme(refs.SignatureScheme(s.scheme))
	}

	return m
}

func (s *Signature) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*refs.Signature)
	if !ok {
		return message.NewUnexpectedMessageType(m, s)
	}

	s.key = v.GetKey()
	s.sign = v.GetSign()
	s.scheme = SignatureScheme(v.GetScheme())

	return nil
}

// ToGRPCMessage forms refs.SubnetID message and returns it as grpc.Message.
func (s *SubnetID) ToGRPCMessage() grpc.Message {
	var m *refs.SubnetID

	if s != nil {
		m = new(refs.SubnetID)

		m.SetValue(s.value)
	}

	return m
}

// FromGRPCMessage restores Info from grpc.Message.
//
// Supported types:
//   - refs.SubnetID.
func (s *SubnetID) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*refs.SubnetID)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	s.value = v.GetValue()

	return nil
}
