package object

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// SetKey sets key to the object attribute.
func (m *Header_Attribute) SetKey(v string) {
	m.Key = v
}

// SetValue sets value of the object attribute.
func (m *Header_Attribute) SetValue(v string) {
	m.Value = v
}

// SetParent sets identifier of the parent object.
func (m *Header_Split) SetParent(v *refs.ObjectID) {
	m.Parent = v
}

// SetPrevious sets identifier of the previous object in split-chain.
func (m *Header_Split) SetPrevious(v *refs.ObjectID) {
	m.Previous = v
}

// SetParentSignature sets signature of the parent object header.
func (m *Header_Split) SetParentSignature(v *refs.Signature) {
	m.ParentSignature = v
}

// SetParentHeader sets parent header structure.
func (m *Header_Split) SetParentHeader(v *Header) {
	m.ParentHeader = v
}

// SetChildren sets list of the identifiers of the child objects.
func (m *Header_Split) SetChildren(v []*refs.ObjectID) {
	m.Children = v
}

// SetSplitId sets split ID of the object.
func (m *Header_Split) SetSplitId(v []byte) {
	m.SplitId = v
}

// SetContainerId sets identifier of the container.
func (m *Header) SetContainerId(v *refs.ContainerID) {
	m.ContainerId = v
}

// SetOwnerId sets identifier of the object owner.
func (m *Header) SetOwnerId(v *refs.OwnerID) {
	m.OwnerId = v
}

// SetCreationEpoch sets creation epoch number.
func (m *Header) SetCreationEpoch(v uint64) {
	m.CreationEpoch = v
}

// SetVersion sets version of the object format.
func (m *Header) SetVersion(v *refs.Version) {
	m.Version = v
}

// SetPayloadLength sets length of the object payload.
func (m *Header) SetPayloadLength(v uint64) {
	m.PayloadLength = v
}

// SetPayloadHash sets hash of the object payload.
func (m *Header) SetPayloadHash(v *refs.Checksum) {
	m.PayloadHash = v
}

// SetObjectType sets type of the object.
func (m *Header) SetObjectType(v ObjectType) {
	m.ObjectType = v
}

// SetHomomorphicHash sets homomorphic hash of the object payload.
func (m *Header) SetHomomorphicHash(v *refs.Checksum) {
	m.HomomorphicHash = v
}

// SetSessionToken sets session token.
func (m *Header) SetSessionToken(v *session.SessionToken) {
	m.SessionToken = v
}

// SetAttributes sets list of the object attributes.
func (m *Header) SetAttributes(v []*Header_Attribute) {
	m.Attributes = v
}

// SetSplit sets split header.
func (m *Header) SetSplit(v *Header_Split) {
	m.Split = v
}

// SetObjectId sets identifier of the object.
func (m *Object) SetObjectId(v *refs.ObjectID) {
	m.ObjectId = v
}

// SetSignature sets signature of the object identifier.
func (m *Object) SetSignature(v *refs.Signature) {
	m.Signature = v
}

// SetHeader sets header of the object.
func (m *Object) SetHeader(v *Header) {
	m.Header = v
}

// SetPayload sets payload bytes of the object.
func (m *Object) SetPayload(v []byte) {
	m.Payload = v
}

// SetVersion sets version of the object.
func (m *ShortHeader) SetVersion(v *refs.Version) {
	m.Version = v
}

// SetCreationEpoch sets creation epoch number.
func (m *ShortHeader) SetCreationEpoch(v uint64) {
	m.CreationEpoch = v
}

// SetOwnerId sets identifier of the object owner.
func (m *ShortHeader) SetOwnerId(v *refs.OwnerID) {
	m.OwnerId = v
}

// SetObjectType sets type of the object.
func (m *ShortHeader) SetObjectType(v ObjectType) {
	m.ObjectType = v
}

// SetPayloadLength sets length of the object payload.
func (m *ShortHeader) SetPayloadLength(v uint64) {
	m.PayloadLength = v
}

// SetPayloadHash sets hash of the object payload.
func (m *ShortHeader) SetPayloadHash(v *refs.Checksum) {
	m.PayloadHash = v
}

// SetHomomorphicHash sets homomorphic hash of the object payload.
func (m *ShortHeader) SetHomomorphicHash(v *refs.Checksum) {
	m.HomomorphicHash = v
}

// SetSplitId sets id of split hierarchy.
func (m *SplitInfo) SetSplitId(v []byte) {
	m.SplitId = v
}

// SetLastPart sets id of most right child in split hierarchy.
func (m *SplitInfo) SetLastPart(v *refs.ObjectID) {
	m.LastPart = v
}

// SetLink sets id of linking object in split hierarchy.
func (m *SplitInfo) SetLink(v *refs.ObjectID) {
	m.Link = v
}

// FromString parses ObjectType from a string representation,
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *ObjectType) FromString(s string) bool {
	i, ok := ObjectType_value[s]
	if ok {
		*x = ObjectType(i)
	}

	return ok
}

// FromString parses MatchType from a string representation,
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *MatchType) FromString(s string) bool {
	i, ok := MatchType_value[s]
	if ok {
		*x = MatchType(i)
	}

	return ok
}
