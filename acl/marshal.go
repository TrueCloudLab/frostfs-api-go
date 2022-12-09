package acl

import (
	acl "github.com/TrueCloudLab/frostfs-api-go/v2/acl/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	protoutil "github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	filterHeaderTypeField = 1
	filterMatchTypeField  = 2
	filterNameField       = 3
	filterValueField      = 4

	targetTypeField = 1
	targetKeysField = 2

	recordOperationField = 1
	recordActionField    = 2
	recordFiltersField   = 3
	recordTargetsField   = 4

	tableVersionField     = 1
	tableContainerIDField = 2
	tableRecordsField     = 3

	lifetimeExpirationField     = 1
	lifetimeNotValidBeforeField = 2
	lifetimeIssuedAtField       = 3

	bearerTokenBodyACLField      = 1
	bearerTokenBodyOwnerField    = 2
	bearerTokenBodyLifetimeField = 3

	bearerTokenBodyField      = 1
	bearerTokenSignatureField = 2
)

// StableMarshal marshals unified acl table structure in a protobuf
// compatible way without field order shuffle.
func (t *Table) StableMarshal(buf []byte) []byte {
	if t == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, t.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(tableVersionField, buf[offset:], t.version)
	offset += protoutil.NestedStructureMarshal(tableContainerIDField, buf[offset:], t.cid)

	for i := range t.records {
		offset += protoutil.NestedStructureMarshal(tableRecordsField, buf[offset:], &t.records[i])
	}

	return buf
}

// StableSize of acl table structure marshalled by StableMarshal function.
func (t *Table) StableSize() (size int) {
	if t == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(tableVersionField, t.version)
	size += protoutil.NestedStructureSize(tableContainerIDField, t.cid)

	for i := range t.records {
		size += protoutil.NestedStructureSize(tableRecordsField, &t.records[i])
	}

	return size
}

func (t *Table) Unmarshal(data []byte) error {
	return message.Unmarshal(t, data, new(acl.EACLTable))
}

// StableMarshal marshals unified acl record structure in a protobuf
// compatible way without field order shuffle.
func (r *Record) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += protoutil.EnumMarshal(recordOperationField, buf[offset:], int32(r.op))
	offset += protoutil.EnumMarshal(recordActionField, buf[offset:], int32(r.action))

	for i := range r.filters {
		offset += protoutil.NestedStructureMarshal(recordFiltersField, buf[offset:], &r.filters[i])
	}

	for i := range r.targets {
		offset += protoutil.NestedStructureMarshal(recordTargetsField, buf[offset:], &r.targets[i])
	}

	return buf
}

// StableSize of acl record structure marshalled by StableMarshal function.
func (r *Record) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.EnumSize(recordOperationField, int32(r.op))
	size += protoutil.EnumSize(recordActionField, int32(r.action))

	for i := range r.filters {
		size += protoutil.NestedStructureSize(recordFiltersField, &r.filters[i])
	}

	for i := range r.targets {
		size += protoutil.NestedStructureSize(recordTargetsField, &r.targets[i])
	}

	return size
}

func (r *Record) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(acl.EACLRecord))
}

// StableMarshal marshals unified header filter structure in a protobuf
// compatible way without field order shuffle.
func (f *HeaderFilter) StableMarshal(buf []byte) []byte {
	if f == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, f.StableSize())
	}

	var offset int

	offset += protoutil.EnumMarshal(filterHeaderTypeField, buf[offset:], int32(f.hdrType))
	offset += protoutil.EnumMarshal(filterMatchTypeField, buf[offset:], int32(f.matchType))
	offset += protoutil.StringMarshal(filterNameField, buf[offset:], f.key)
	protoutil.StringMarshal(filterValueField, buf[offset:], f.value)

	return buf
}

// StableSize of header filter structure marshalled by StableMarshal function.
func (f *HeaderFilter) StableSize() (size int) {
	if f == nil {
		return 0
	}

	size += protoutil.EnumSize(filterHeaderTypeField, int32(f.hdrType))
	size += protoutil.EnumSize(filterMatchTypeField, int32(f.matchType))
	size += protoutil.StringSize(filterNameField, f.key)
	size += protoutil.StringSize(filterValueField, f.value)

	return size
}

func (f *HeaderFilter) Unmarshal(data []byte) error {
	return message.Unmarshal(f, data, new(acl.EACLRecord_Filter))
}

// StableMarshal marshals unified role info structure in a protobuf
// compatible way without field order shuffle.
func (t *Target) StableMarshal(buf []byte) []byte {
	if t == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, t.StableSize())
	}

	var offset int

	offset += protoutil.EnumMarshal(targetTypeField, buf[offset:], int32(t.role))
	protoutil.RepeatedBytesMarshal(targetKeysField, buf[offset:], t.keys)

	return buf
}

// StableSize of role info structure marshalled by StableMarshal function.
func (t *Target) StableSize() (size int) {
	if t == nil {
		return 0
	}

	size += protoutil.EnumSize(targetTypeField, int32(t.role))
	size += protoutil.RepeatedBytesSize(targetKeysField, t.keys)

	return size
}

func (t *Target) Unmarshal(data []byte) error {
	return message.Unmarshal(t, data, new(acl.EACLRecord_Target))
}

func (l *TokenLifetime) StableMarshal(buf []byte) []byte {
	if l == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, l.StableSize())
	}

	var offset int

	offset += protoutil.UInt64Marshal(lifetimeExpirationField, buf[offset:], l.exp)
	offset += protoutil.UInt64Marshal(lifetimeNotValidBeforeField, buf[offset:], l.nbf)
	protoutil.UInt64Marshal(lifetimeIssuedAtField, buf[offset:], l.iat)

	return buf
}

func (l *TokenLifetime) StableSize() (size int) {
	if l == nil {
		return 0
	}

	size += protoutil.UInt64Size(lifetimeExpirationField, l.exp)
	size += protoutil.UInt64Size(lifetimeNotValidBeforeField, l.nbf)
	size += protoutil.UInt64Size(lifetimeIssuedAtField, l.iat)

	return size
}

func (l *TokenLifetime) Unmarshal(data []byte) error {
	return message.Unmarshal(l, data, new(acl.BearerToken_Body_TokenLifetime))
}

func (bt *BearerTokenBody) StableMarshal(buf []byte) []byte {
	if bt == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, bt.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(bearerTokenBodyACLField, buf[offset:], bt.eacl)
	offset += protoutil.NestedStructureMarshal(bearerTokenBodyOwnerField, buf[offset:], bt.ownerID)
	protoutil.NestedStructureMarshal(bearerTokenBodyLifetimeField, buf[offset:], bt.lifetime)

	return buf
}

func (bt *BearerTokenBody) StableSize() (size int) {
	if bt == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(bearerTokenBodyACLField, bt.eacl)
	size += protoutil.NestedStructureSize(bearerTokenBodyOwnerField, bt.ownerID)
	size += protoutil.NestedStructureSize(bearerTokenBodyLifetimeField, bt.lifetime)

	return size
}

func (bt *BearerTokenBody) Unmarshal(data []byte) error {
	return message.Unmarshal(bt, data, new(acl.BearerToken_Body))
}

func (bt *BearerToken) StableMarshal(buf []byte) []byte {
	if bt == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, bt.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(bearerTokenBodyField, buf[offset:], bt.body)
	protoutil.NestedStructureMarshal(bearerTokenSignatureField, buf[offset:], bt.sig)

	return buf
}

func (bt *BearerToken) StableSize() (size int) {
	if bt == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(bearerTokenBodyField, bt.body)
	size += protoutil.NestedStructureSize(bearerTokenSignatureField, bt.sig)

	return size
}

func (bt *BearerToken) Unmarshal(data []byte) error {
	return message.Unmarshal(bt, data, new(acl.BearerToken))
}
