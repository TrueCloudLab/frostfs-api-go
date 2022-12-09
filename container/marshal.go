package container

import (
	container "github.com/TrueCloudLab/frostfs-api-go/v2/container/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	protoutil "github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	attributeKeyField   = 1
	attributeValueField = 2

	containerVersionField    = 1
	containerOwnerField      = 2
	containerNonceField      = 3
	containerBasicACLField   = 4
	containerAttributesField = 5
	containerPlacementField  = 6

	putReqBodyContainerField = 1
	putReqBodySignatureField = 2

	putRespBodyIDField = 1

	deleteReqBodyIDField        = 1
	deleteReqBodySignatureField = 2

	getReqBodyIDField = 1

	getRespBodyContainerField = 1
	getRespBodySignatureField = 2
	getRespBodyTokenField     = 3

	listReqBodyOwnerField = 1

	listRespBodyIDsField = 1

	setEACLReqBodyTableField     = 1
	setEACLReqBodySignatureField = 2

	getEACLReqBodyIDField = 1

	getEACLRespBodyTableField     = 1
	getEACLRespBodySignatureField = 2
	getEACLRespBodyTokenField     = 3

	usedSpaceAnnounceEpochField     = 1
	usedSpaceAnnounceCIDField       = 2
	usedSpaceAnnounceUsedSpaceField = 3

	usedSpaceReqBodyAnnouncementsField = 1
)

func (a *Attribute) StableMarshal(buf []byte) []byte {
	if a == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, a.StableSize())
	}

	var offset int

	offset += protoutil.StringMarshal(attributeKeyField, buf[offset:], a.key)
	protoutil.StringMarshal(attributeValueField, buf[offset:], a.val)

	return buf
}

func (a *Attribute) StableSize() (size int) {
	if a == nil {
		return 0
	}

	size += protoutil.StringSize(attributeKeyField, a.key)
	size += protoutil.StringSize(attributeValueField, a.val)

	return size
}

func (a *Attribute) Unmarshal(data []byte) error {
	return message.Unmarshal(a, data, new(container.Container_Attribute))
}

func (c *Container) StableMarshal(buf []byte) []byte {
	if c == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, c.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(containerVersionField, buf[offset:], c.version)
	offset += protoutil.NestedStructureMarshal(containerOwnerField, buf[offset:], c.ownerID)
	offset += protoutil.BytesMarshal(containerNonceField, buf[offset:], c.nonce)
	offset += protoutil.UInt32Marshal(containerBasicACLField, buf[offset:], c.basicACL)

	for i := range c.attr {
		offset += protoutil.NestedStructureMarshal(containerAttributesField, buf[offset:], &c.attr[i])
	}

	protoutil.NestedStructureMarshal(containerPlacementField, buf[offset:], c.policy)

	return buf
}

func (c *Container) StableSize() (size int) {
	if c == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(containerVersionField, c.version)
	size += protoutil.NestedStructureSize(containerOwnerField, c.ownerID)
	size += protoutil.BytesSize(containerNonceField, c.nonce)
	size += protoutil.UInt32Size(containerBasicACLField, c.basicACL)

	for i := range c.attr {
		size += protoutil.NestedStructureSize(containerAttributesField, &c.attr[i])
	}

	size += protoutil.NestedStructureSize(containerPlacementField, c.policy)

	return size
}

func (c *Container) Unmarshal(data []byte) error {
	return message.Unmarshal(c, data, new(container.Container))
}

func (r *PutRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(putReqBodyContainerField, buf[offset:], r.cnr)
	protoutil.NestedStructureMarshal(putReqBodySignatureField, buf[offset:], r.sig)

	return buf
}

func (r *PutRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(putReqBodyContainerField, r.cnr)
	size += protoutil.NestedStructureSize(putReqBodySignatureField, r.sig)

	return size
}

func (r *PutRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.PutRequest_Body))
}

func (r *PutResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	protoutil.NestedStructureMarshal(putRespBodyIDField, buf, r.cid)

	return buf
}

func (r *PutResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(putRespBodyIDField, r.cid)

	return size
}

func (r *PutResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.PutResponse_Body))
}

func (r *DeleteRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(deleteReqBodyIDField, buf[offset:], r.cid)
	protoutil.NestedStructureMarshal(deleteReqBodySignatureField, buf[offset:], r.sig)

	return buf
}

func (r *DeleteRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(deleteReqBodyIDField, r.cid)
	size += protoutil.NestedStructureSize(deleteReqBodySignatureField, r.sig)

	return size
}

func (r *DeleteRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.DeleteRequest_Body))
}

func (r *DeleteResponseBody) StableMarshal(buf []byte) []byte {
	return nil
}

func (r *DeleteResponseBody) StableSize() (size int) {
	return 0
}

func (r *DeleteResponseBody) Unmarshal([]byte) error {
	return nil
}

func (r *GetRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	protoutil.NestedStructureMarshal(getReqBodyIDField, buf, r.cid)

	return buf
}

func (r *GetRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(getReqBodyIDField, r.cid)

	return size
}

func (r *GetRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.GetRequest_Body))
}

func (r *GetResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(getRespBodyContainerField, buf, r.cnr)
	offset += protoutil.NestedStructureMarshal(getRespBodySignatureField, buf[offset:], r.sig)
	protoutil.NestedStructureMarshal(getRespBodyTokenField, buf[offset:], r.token)

	return buf
}

func (r *GetResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(getRespBodyContainerField, r.cnr)
	size += protoutil.NestedStructureSize(getRespBodySignatureField, r.sig)
	size += protoutil.NestedStructureSize(getRespBodyTokenField, r.token)

	return size
}

func (r *GetResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.GetResponse_Body))
}

func (r *ListRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	protoutil.NestedStructureMarshal(listReqBodyOwnerField, buf, r.ownerID)

	return buf
}

func (r *ListRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(listReqBodyOwnerField, r.ownerID)

	return size
}

func (r *ListRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.ListRequest_Body))
}

func (r *ListResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	for i := range r.cidList {
		offset += protoutil.NestedStructureMarshal(listRespBodyIDsField, buf[offset:], &r.cidList[i])
	}

	return buf
}

func (r *ListResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	for i := range r.cidList {
		size += protoutil.NestedStructureSize(listRespBodyIDsField, &r.cidList[i])
	}

	return size
}

func (r *ListResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.ListResponse_Body))
}

func (r *SetExtendedACLRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(setEACLReqBodyTableField, buf[offset:], r.eacl)
	protoutil.NestedStructureMarshal(setEACLReqBodySignatureField, buf[offset:], r.sig)

	return buf
}

func (r *SetExtendedACLRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(setEACLReqBodyTableField, r.eacl)
	size += protoutil.NestedStructureSize(setEACLReqBodySignatureField, r.sig)

	return size
}

func (r *SetExtendedACLRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.SetExtendedACLRequest_Body))
}

func (r *SetExtendedACLResponseBody) StableMarshal(buf []byte) []byte {
	return nil
}

func (r *SetExtendedACLResponseBody) StableSize() (size int) {
	return 0
}

func (r *SetExtendedACLResponseBody) Unmarshal([]byte) error {
	return nil
}

func (r *GetExtendedACLRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	protoutil.NestedStructureMarshal(getEACLReqBodyIDField, buf, r.cid)

	return buf
}

func (r *GetExtendedACLRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(getEACLReqBodyIDField, r.cid)

	return size
}

func (r *GetExtendedACLRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.GetExtendedACLRequest_Body))
}

func (r *GetExtendedACLResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(getEACLRespBodyTableField, buf[offset:], r.eacl)
	offset += protoutil.NestedStructureMarshal(getEACLRespBodySignatureField, buf[offset:], r.sig)
	protoutil.NestedStructureMarshal(getEACLRespBodyTokenField, buf[offset:], r.token)

	return buf
}

func (r *GetExtendedACLResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(getEACLRespBodyTableField, r.eacl)
	size += protoutil.NestedStructureSize(getEACLRespBodySignatureField, r.sig)
	size += protoutil.NestedStructureSize(getEACLRespBodyTokenField, r.token)

	return size
}

func (r *GetExtendedACLResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.GetExtendedACLResponse_Body))
}

func (a *UsedSpaceAnnouncement) StableMarshal(buf []byte) []byte {
	if a == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, a.StableSize())
	}

	var offset int

	offset += protoutil.UInt64Marshal(usedSpaceAnnounceEpochField, buf[offset:], a.epoch)
	offset += protoutil.NestedStructureMarshal(usedSpaceAnnounceCIDField, buf[offset:], a.cid)
	protoutil.UInt64Marshal(usedSpaceAnnounceUsedSpaceField, buf[offset:], a.usedSpace)

	return buf
}

func (a *UsedSpaceAnnouncement) StableSize() (size int) {
	if a == nil {
		return 0
	}

	size += protoutil.UInt64Size(usedSpaceAnnounceEpochField, a.epoch)
	size += protoutil.NestedStructureSize(usedSpaceAnnounceCIDField, a.cid)
	size += protoutil.UInt64Size(usedSpaceAnnounceUsedSpaceField, a.usedSpace)

	return size
}

func (a *UsedSpaceAnnouncement) Unmarshal(data []byte) error {
	return message.Unmarshal(a, data, new(container.AnnounceUsedSpaceRequest_Body_Announcement))
}

func (r *AnnounceUsedSpaceRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	for i := range r.announcements {
		offset += protoutil.NestedStructureMarshal(usedSpaceReqBodyAnnouncementsField, buf[offset:], &r.announcements[i])
	}

	return buf
}

func (r *AnnounceUsedSpaceRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	for i := range r.announcements {
		size += protoutil.NestedStructureSize(usedSpaceReqBodyAnnouncementsField, &r.announcements[i])
	}

	return size
}

func (r *AnnounceUsedSpaceRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(container.AnnounceUsedSpaceRequest_Body))
}

func (r *AnnounceUsedSpaceResponseBody) StableMarshal(buf []byte) []byte {
	return nil
}

func (r *AnnounceUsedSpaceResponseBody) StableSize() (size int) {
	return 0
}

func (r *AnnounceUsedSpaceResponseBody) Unmarshal([]byte) error {
	return nil
}
