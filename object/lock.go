package object

import (
	"errors"
	"fmt"

	lock "github.com/TrueCloudLab/frostfs-api-go/v2/lock/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

// Lock represents object Lock message from NeoFS API V2 protocol.
type Lock struct {
	members []refs.ObjectID
}

// NumberOfMembers returns length of lock list.
func (x *Lock) NumberOfMembers() int {
	if x != nil {
		return len(x.members)
	}

	return 0
}

// IterateMembers passes members of the lock list to f.
func (x *Lock) IterateMembers(f func(refs.ObjectID)) {
	if x != nil {
		for i := range x.members {
			f(x.members[i])
		}
	}
}

// SetMembers sets list of locked members.
// Arg must not be mutated for the duration of the Lock.
func (x *Lock) SetMembers(ids []refs.ObjectID) {
	x.members = ids
}

const (
	_ = iota
	fNumLockMembers
)

// StableMarshal encodes the Lock into Protocol Buffers binary format
// with direct field order.
func (x *Lock) StableMarshal(buf []byte) []byte {
	if x == nil || len(x.members) == 0 {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	for i := range x.members {
		offset += proto.NestedStructureMarshal(fNumLockMembers, buf[offset:], &x.members[i])
	}

	return buf
}

// StableSize size of the buffer required to write the Lock in Protocol Buffers
// binary format.
func (x *Lock) StableSize() (sz int) {
	if x != nil {
		for i := range x.members {
			sz += proto.NestedStructureSize(fNumLockMembers, &x.members[i])
		}
	}

	return
}

// Unmarshal decodes the Lock from its Protocol Buffers binary format.
func (x *Lock) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(lock.Lock))
}

func (x *Lock) ToGRPCMessage() grpc.Message {
	var m *lock.Lock

	if x != nil {
		m = new(lock.Lock)

		var members []*refsGRPC.ObjectID

		if x.members != nil {
			members = make([]*refsGRPC.ObjectID, len(x.members))

			for i := range x.members {
				members[i] = x.members[i].ToGRPCMessage().(*refsGRPC.ObjectID)
			}
		}

		m.SetMembers(members)
	}

	return m
}

func (x *Lock) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*lock.Lock)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	members := v.GetMembers()
	if members == nil {
		x.members = nil
	} else {
		x.members = make([]refs.ObjectID, len(members))
		var err error

		for i := range x.members {
			err = x.members[i].FromGRPCMessage(members[i])
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// WriteLock writes Lock to the Object as a payload content.
// The object must not be nil.
func WriteLock(obj *Object, lock Lock) {
	hdr := obj.GetHeader()
	if hdr == nil {
		hdr = new(Header)
		obj.SetHeader(hdr)
	}

	hdr.SetObjectType(TypeLock)

	payload := lock.StableMarshal(nil)
	obj.SetPayload(payload)
}

// ReadLock reads Lock from the Object payload content.
func ReadLock(lock *Lock, obj Object) error {
	payload := obj.GetPayload()
	if len(payload) == 0 {
		return errors.New("empty payload")
	}

	err := lock.Unmarshal(payload)
	if err != nil {
		return fmt.Errorf("decode lock content from payload: %w", err)
	}

	return nil
}
