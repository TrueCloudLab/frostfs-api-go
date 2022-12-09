package refs

import (
	"encoding/binary"

	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	ownerIDValField = 1

	containerIDValField = 1

	objectIDValField = 1

	addressContainerField = 1
	addressObjectField    = 2

	checksumTypeField  = 1
	checksumValueField = 2

	signatureKeyField    = 1
	signatureValueField  = 2
	signatureSchemeField = 3

	versionMajorField = 1
	versionMinorField = 2
)

func (o *OwnerID) StableMarshal(buf []byte) []byte {
	if o == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, o.StableSize())
	}

	proto.BytesMarshal(ownerIDValField, buf, o.val)

	return buf
}

func (o *OwnerID) StableSize() int {
	if o == nil {
		return 0
	}

	return proto.BytesSize(ownerIDValField, o.val)
}

func (o *OwnerID) Unmarshal(data []byte) error {
	return message.Unmarshal(o, data, new(refs.OwnerID))
}

func (c *ContainerID) StableMarshal(buf []byte) []byte {
	if c == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, c.StableSize())
	}

	proto.BytesMarshal(containerIDValField, buf, c.val)

	return buf
}

func (c *ContainerID) StableSize() int {
	if c == nil {
		return 0
	}

	return proto.BytesSize(containerIDValField, c.val)
}

func (c *ContainerID) Unmarshal(data []byte) error {
	return message.Unmarshal(c, data, new(refs.ContainerID))
}

func (o *ObjectID) StableMarshal(buf []byte) []byte {
	if o == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, o.StableSize())
	}

	proto.BytesMarshal(objectIDValField, buf, o.val)

	return buf
}

// ObjectIDNestedListSize returns byte length of nested
// repeated ObjectID field with fNum number.
func ObjectIDNestedListSize(fNum int64, ids []ObjectID) (sz int) {
	for i := range ids {
		sz += proto.NestedStructureSize(fNum, &ids[i])
	}

	return
}

func (o *ObjectID) StableSize() int {
	if o == nil {
		return 0
	}

	return proto.BytesSize(objectIDValField, o.val)
}

// ObjectIDNestedListMarshal writes protobuf repeated ObjectID field
// with fNum number to buf.
func ObjectIDNestedListMarshal(fNum int64, buf []byte, ids []ObjectID) (off int) {
	prefix, _ := proto.NestedStructurePrefix(fNum)
	for i := range ids {
		off += binary.PutUvarint(buf[off:], prefix)

		n := ids[i].StableSize()
		off += binary.PutUvarint(buf[off:], uint64(n))
		off += proto.BytesMarshal(objectIDValField, buf[off:], ids[i].val)
	}

	return
}

func (o *ObjectID) Unmarshal(data []byte) error {
	return message.Unmarshal(o, data, new(refs.ObjectID))
}

func (a *Address) StableMarshal(buf []byte) []byte {
	if a == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, a.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(addressContainerField, buf[offset:], a.cid)
	proto.NestedStructureMarshal(addressObjectField, buf[offset:], a.oid)

	return buf
}

func (a *Address) StableSize() (size int) {
	if a == nil {
		return 0
	}

	size += proto.NestedStructureSize(addressContainerField, a.cid)
	size += proto.NestedStructureSize(addressObjectField, a.oid)

	return size
}

func (a *Address) Unmarshal(data []byte) error {
	return message.Unmarshal(a, data, new(refs.Address))
}

func (c *Checksum) StableMarshal(buf []byte) []byte {
	if c == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, c.StableSize())
	}

	var offset int

	offset += proto.EnumMarshal(checksumTypeField, buf[offset:], int32(c.typ))
	proto.BytesMarshal(checksumValueField, buf[offset:], c.sum)

	return buf
}

func (c *Checksum) StableSize() (size int) {
	if c == nil {
		return 0
	}

	size += proto.EnumSize(checksumTypeField, int32(c.typ))
	size += proto.BytesSize(checksumValueField, c.sum)

	return size
}

func (c *Checksum) Unmarshal(data []byte) error {
	return message.Unmarshal(c, data, new(refs.Checksum))
}

func (s *Signature) StableMarshal(buf []byte) []byte {
	if s == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, s.StableSize())
	}

	var offset int

	offset += proto.BytesMarshal(signatureKeyField, buf[offset:], s.key)
	offset += proto.BytesMarshal(signatureValueField, buf[offset:], s.sign)
	proto.EnumMarshal(signatureSchemeField, buf[offset:], int32(s.scheme))

	return buf
}

func (s *Signature) StableSize() (size int) {
	if s == nil {
		return 0
	}

	size += proto.BytesSize(signatureKeyField, s.key)
	size += proto.BytesSize(signatureValueField, s.sign)
	size += proto.EnumSize(signatureSchemeField, int32(s.scheme))

	return size
}

func (s *Signature) Unmarshal(data []byte) error {
	return message.Unmarshal(s, data, new(refs.Signature))
}

func (v *Version) StableMarshal(buf []byte) []byte {
	if v == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, v.StableSize())
	}

	var offset int

	offset += proto.UInt32Marshal(versionMajorField, buf[offset:], v.major)
	proto.UInt32Marshal(versionMinorField, buf[offset:], v.minor)

	return buf
}

func (v *Version) StableSize() (size int) {
	if v == nil {
		return 0
	}

	size += proto.UInt32Size(versionMajorField, v.major)
	size += proto.UInt32Size(versionMinorField, v.minor)

	return size
}

func (v *Version) Unmarshal(data []byte) error {
	return message.Unmarshal(v, data, new(refs.Version))
}

// SubnetID message field numbers
const (
	_ = iota
	subnetIDValFNum
)

// StableMarshal marshals SubnetID to NeoFS API V2 binary format (Protocol Buffers with direct field order).
//
// Returns a slice of recorded data. Data is written to the provided buffer if there is enough space.
func (s *SubnetID) StableMarshal(buf []byte) []byte {
	if s == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, s.StableSize())
	}

	proto.Fixed32Marshal(subnetIDValFNum, buf, s.value)

	return buf
}

// StableSize returns the number of bytes required to write SubnetID in NeoFS API V2 binary format (see StableMarshal).
func (s *SubnetID) StableSize() (size int) {
	if s != nil {
		size += proto.Fixed32Size(subnetIDValFNum, s.value)
	}

	return
}

// Unmarshal unmarshals SubnetID from NeoFS API V2 binary format (see StableMarshal).
// Must not be called on nil.
//
// Note: empty data corresponds to zero ID value or nil pointer to it.
func (s *SubnetID) Unmarshal(data []byte) error {
	return message.Unmarshal(s, data, new(refs.SubnetID))
}
