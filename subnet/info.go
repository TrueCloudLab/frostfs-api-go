package subnet

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsgrpc "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	subnet "github.com/TrueCloudLab/frostfs-api-go/v2/subnet/grpc"
	protoutil "github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

// Info represents information about NeoFS subnet. Structure is compatible with NeoFS API V2 protocol.
//
// Zero value represents zero subnet w/o an owner.
type Info struct {
	id *refs.SubnetID

	owner *refs.OwnerID
}

// ID returns identifier of the subnet. Nil return is equivalent to zero subnet ID.
func (x *Info) ID() *refs.SubnetID {
	return x.id
}

// SetID returns identifier of the subnet. Nil arg is equivalent to zero subnet ID.
func (x *Info) SetID(id *refs.SubnetID) {
	x.id = id
}

// Owner returns subnet owner's ID in NeoFS system.
func (x *Info) Owner() *refs.OwnerID {
	return x.owner
}

// SetOwner sets subnet owner's ID in NeoFS system.
func (x *Info) SetOwner(id *refs.OwnerID) {
	x.owner = id
}

// ToGRPCMessage forms subnet.SubnetInfo message and returns it as grpc.Message.
func (x *Info) ToGRPCMessage() grpc.Message {
	var m *subnet.SubnetInfo

	if x != nil {
		m = new(subnet.SubnetInfo)

		m.SetID(x.id.ToGRPCMessage().(*refsgrpc.SubnetID))
		m.SetOwner(x.owner.ToGRPCMessage().(*refsgrpc.OwnerID))
	}

	return m
}

// FromGRPCMessage restores Info from grpc.Message.
//
// Supported types:
//   - subnet.SubnetInfo.
func (x *Info) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*subnet.SubnetInfo)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	id := v.GetId()
	if id == nil {
		x.id = nil
	} else {
		if x.id == nil {
			x.id = new(refs.SubnetID)
		}

		err = x.id.FromGRPCMessage(id)
		if err != nil {
			return err
		}
	}

	ownerID := v.GetOwner()
	if ownerID == nil {
		x.owner = nil
	} else {
		if x.owner == nil {
			x.owner = new(refs.OwnerID)
		}

		err = x.owner.FromGRPCMessage(ownerID)
		if err != nil {
			return err
		}
	}

	return nil
}

// SubnetInfo message field numbers
const (
	_ = iota
	subnetInfoIDFNum
	subnetInfoOwnerFNum
)

// StableMarshal marshals Info to NeoFS API V2 binary format (Protocol Buffers with direct field order).
//
// Returns a slice of recorded data. Data is written to the provided buffer if there is enough space.
func (x *Info) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(subnetInfoIDFNum, buf[offset:], x.id)
	protoutil.NestedStructureMarshal(subnetInfoOwnerFNum, buf[offset:], x.owner)

	return buf
}

// StableSize returns the number of bytes required to write Info in NeoFS API V2 binary format (see StableMarshal).
func (x *Info) StableSize() (size int) {
	if x != nil {
		size += protoutil.NestedStructureSize(subnetInfoIDFNum, x.id)
		size += protoutil.NestedStructureSize(subnetInfoOwnerFNum, x.owner)
	}

	return
}

// Unmarshal decodes Info from NeoFS API V2 binary format (see StableMarshal).
func (x *Info) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(subnet.SubnetInfo))
}
