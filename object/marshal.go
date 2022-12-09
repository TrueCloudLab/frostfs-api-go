package object

import (
	object "github.com/TrueCloudLab/frostfs-api-go/v2/object/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	shortHdrVersionField    = 1
	shortHdrEpochField      = 2
	shortHdrOwnerField      = 3
	shortHdrObjectTypeField = 4
	shortHdrPayloadLength   = 5
	shortHdrHashField       = 6
	shortHdrHomoHashField   = 7

	attributeKeyField   = 1
	attributeValueField = 2

	splitHdrParentField          = 1
	splitHdrPreviousField        = 2
	splitHdrParentSignatureField = 3
	splitHdrParentHeaderField    = 4
	splitHdrChildrenField        = 5
	splitHdrSplitIDField         = 6

	hdrVersionField         = 1
	hdrContainerIDField     = 2
	hdrOwnerIDField         = 3
	hdrEpochField           = 4
	hdrPayloadLengthField   = 5
	hdrPayloadHashField     = 6
	hdrObjectTypeField      = 7
	hdrHomomorphicHashField = 8
	hdrSessionTokenField    = 9
	hdrAttributesField      = 10
	hdrSplitField           = 11

	hdrWithSigHeaderField    = 1
	hdrWithSigSignatureField = 2

	objIDField        = 1
	objSignatureField = 2
	objHeaderField    = 3
	objPayloadField   = 4

	splitInfoSplitIDField  = 1
	splitInfoLastPartField = 2
	splitInfoLinkField     = 3

	getReqBodyAddressField = 1
	getReqBodyRawFlagField = 2

	getRespInitObjectIDField  = 1
	getRespInitSignatureField = 2
	getRespInitHeaderField    = 3

	getRespBodyInitField      = 1
	getRespBodyChunkField     = 2
	getRespBodySplitInfoField = 3

	putReqInitObjectIDField  = 1
	putReqInitSignatureField = 2
	putReqInitHeaderField    = 3
	putReqInitCopiesNumField = 4

	putReqBodyInitField  = 1
	putReqBodyChunkField = 2

	putRespBodyObjectIDField = 1

	deleteReqBodyAddressField = 1

	deleteRespBodyTombstoneFNum = 1

	headReqBodyAddressField  = 1
	headReqBodyMainFlagField = 2
	headReqBodyRawFlagField  = 3

	headRespBodyHeaderField      = 1
	headRespBodyShortHeaderField = 2
	headRespBodySplitInfoField   = 3

	searchFilterMatchField = 1
	searchFilterNameField  = 2
	searchFilterValueField = 3

	searchReqBodyContainerIDField = 1
	searchReqBodyVersionField     = 2
	searchReqBodyFiltersField     = 3

	searchRespBodyObjectIDsField = 1

	rangeOffsetField = 1
	rangeLengthField = 2

	getRangeReqBodyAddressField = 1
	getRangeReqBodyRangeField   = 2
	getRangeReqBodyRawField     = 3

	getRangeRespChunkField     = 1
	getRangeRespSplitInfoField = 2

	getRangeHashReqBodyAddressField = 1
	getRangeHashReqBodyRangesField  = 2
	getRangeHashReqBodySaltField    = 3
	getRangeHashReqBodyTypeField    = 4

	getRangeHashRespBodyTypeField     = 1
	getRangeHashRespBodyHashListField = 2
)

func (h *ShortHeader) StableMarshal(buf []byte) []byte {
	if h == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, h.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(shortHdrVersionField, buf[offset:], h.version)
	offset += proto.UInt64Marshal(shortHdrEpochField, buf[offset:], h.creatEpoch)
	offset += proto.NestedStructureMarshal(shortHdrOwnerField, buf[offset:], h.ownerID)
	offset += proto.EnumMarshal(shortHdrObjectTypeField, buf[offset:], int32(h.typ))
	offset += proto.UInt64Marshal(shortHdrPayloadLength, buf[offset:], h.payloadLen)
	offset += proto.NestedStructureMarshal(shortHdrHashField, buf[offset:], h.payloadHash)
	proto.NestedStructureMarshal(shortHdrHomoHashField, buf[offset:], h.homoHash)

	return buf
}

func (h *ShortHeader) StableSize() (size int) {
	if h == nil {
		return 0
	}

	size += proto.NestedStructureSize(shortHdrVersionField, h.version)
	size += proto.UInt64Size(shortHdrEpochField, h.creatEpoch)
	size += proto.NestedStructureSize(shortHdrOwnerField, h.ownerID)
	size += proto.EnumSize(shortHdrObjectTypeField, int32(h.typ))
	size += proto.UInt64Size(shortHdrPayloadLength, h.payloadLen)
	size += proto.NestedStructureSize(shortHdrHashField, h.payloadHash)
	size += proto.NestedStructureSize(shortHdrHomoHashField, h.homoHash)

	return size
}

func (h *ShortHeader) Unmarshal(data []byte) error {
	return message.Unmarshal(h, data, new(object.ShortHeader))
}

func (a *Attribute) StableMarshal(buf []byte) []byte {
	if a == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, a.StableSize())
	}

	var offset int

	offset += proto.StringMarshal(attributeKeyField, buf[offset:], a.key)
	proto.StringMarshal(attributeValueField, buf[offset:], a.val)

	return buf
}

func (a *Attribute) StableSize() (size int) {
	if a == nil {
		return 0
	}

	size += proto.StringSize(shortHdrVersionField, a.key)
	size += proto.StringSize(shortHdrEpochField, a.val)

	return size
}

func (a *Attribute) Unmarshal(data []byte) error {
	return message.Unmarshal(a, data, new(object.Header_Attribute))
}

func (h *SplitHeader) StableMarshal(buf []byte) []byte {
	if h == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, h.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(splitHdrParentField, buf[offset:], h.par)
	offset += proto.NestedStructureMarshal(splitHdrPreviousField, buf[offset:], h.prev)
	offset += proto.NestedStructureMarshal(splitHdrParentSignatureField, buf[offset:], h.parSig)
	offset += proto.NestedStructureMarshal(splitHdrParentHeaderField, buf[offset:], h.parHdr)
	offset += refs.ObjectIDNestedListMarshal(splitHdrChildrenField, buf[offset:], h.children)
	proto.BytesMarshal(splitHdrSplitIDField, buf[offset:], h.splitID)

	return buf
}

func (h *SplitHeader) StableSize() (size int) {
	if h == nil {
		return 0
	}

	size += proto.NestedStructureSize(splitHdrParentField, h.par)
	size += proto.NestedStructureSize(splitHdrPreviousField, h.prev)
	size += proto.NestedStructureSize(splitHdrParentSignatureField, h.parSig)
	size += proto.NestedStructureSize(splitHdrParentHeaderField, h.parHdr)
	size += refs.ObjectIDNestedListSize(splitHdrChildrenField, h.children)
	size += proto.BytesSize(splitHdrSplitIDField, h.splitID)

	return size
}

func (h *SplitHeader) Unmarshal(data []byte) error {
	return message.Unmarshal(h, data, new(object.Header_Split))
}

func (h *Header) StableMarshal(buf []byte) []byte {
	if h == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, h.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(hdrVersionField, buf[offset:], h.version)
	offset += proto.NestedStructureMarshal(hdrContainerIDField, buf[offset:], h.cid)
	offset += proto.NestedStructureMarshal(hdrOwnerIDField, buf[offset:], h.ownerID)
	offset += proto.UInt64Marshal(hdrEpochField, buf[offset:], h.creatEpoch)
	offset += proto.UInt64Marshal(hdrPayloadLengthField, buf[offset:], h.payloadLen)
	offset += proto.NestedStructureMarshal(hdrPayloadHashField, buf[offset:], h.payloadHash)
	offset += proto.EnumMarshal(hdrObjectTypeField, buf[offset:], int32(h.typ))
	offset += proto.NestedStructureMarshal(hdrHomomorphicHashField, buf[offset:], h.homoHash)
	offset += proto.NestedStructureMarshal(hdrSessionTokenField, buf[offset:], h.sessionToken)

	for i := range h.attr {
		offset += proto.NestedStructureMarshal(hdrAttributesField, buf[offset:], &h.attr[i])
	}

	proto.NestedStructureMarshal(hdrSplitField, buf[offset:], h.split)

	return buf
}

func (h *Header) StableSize() (size int) {
	if h == nil {
		return 0
	}

	size += proto.NestedStructureSize(hdrVersionField, h.version)
	size += proto.NestedStructureSize(hdrContainerIDField, h.cid)
	size += proto.NestedStructureSize(hdrOwnerIDField, h.ownerID)
	size += proto.UInt64Size(hdrEpochField, h.creatEpoch)
	size += proto.UInt64Size(hdrPayloadLengthField, h.payloadLen)
	size += proto.NestedStructureSize(hdrPayloadHashField, h.payloadHash)
	size += proto.EnumSize(hdrObjectTypeField, int32(h.typ))
	size += proto.NestedStructureSize(hdrHomomorphicHashField, h.homoHash)
	size += proto.NestedStructureSize(hdrSessionTokenField, h.sessionToken)
	for i := range h.attr {
		size += proto.NestedStructureSize(hdrAttributesField, &h.attr[i])
	}
	size += proto.NestedStructureSize(hdrSplitField, h.split)

	return size
}

func (h *Header) Unmarshal(data []byte) error {
	return message.Unmarshal(h, data, new(object.Header))
}

func (h *HeaderWithSignature) StableMarshal(buf []byte) []byte {
	if h == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, h.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(hdrWithSigHeaderField, buf[offset:], h.header)
	proto.NestedStructureMarshal(hdrWithSigSignatureField, buf[offset:], h.signature)

	return buf
}

func (h *HeaderWithSignature) StableSize() (size int) {
	if h == nil {
		return 0
	}

	size += proto.NestedStructureSize(hdrVersionField, h.header)
	size += proto.NestedStructureSize(hdrContainerIDField, h.signature)

	return size
}

func (h *HeaderWithSignature) Unmarshal(data []byte) error {
	return message.Unmarshal(h, data, new(object.HeaderWithSignature))
}

func (o *Object) StableMarshal(buf []byte) []byte {
	if o == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, o.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(objIDField, buf[offset:], o.objectID)
	offset += proto.NestedStructureMarshal(objSignatureField, buf[offset:], o.idSig)
	offset += proto.NestedStructureMarshal(objHeaderField, buf[offset:], o.header)
	proto.BytesMarshal(objPayloadField, buf[offset:], o.payload)

	return buf
}

func (o *Object) StableSize() (size int) {
	if o == nil {
		return 0
	}

	size += proto.NestedStructureSize(objIDField, o.objectID)
	size += proto.NestedStructureSize(objSignatureField, o.idSig)
	size += proto.NestedStructureSize(objHeaderField, o.header)
	size += proto.BytesSize(objPayloadField, o.payload)

	return size
}

func (o *Object) Unmarshal(data []byte) error {
	return message.Unmarshal(o, data, new(object.Object))
}

func (s *SplitInfo) StableMarshal(buf []byte) []byte {
	if s == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, s.StableSize())
	}

	var offset int

	offset += proto.BytesMarshal(splitInfoSplitIDField, buf[offset:], s.splitID)
	offset += proto.NestedStructureMarshal(splitInfoLastPartField, buf[offset:], s.lastPart)
	proto.NestedStructureMarshal(splitInfoLinkField, buf[offset:], s.link)

	return buf
}

func (s *SplitInfo) StableSize() (size int) {
	if s == nil {
		return 0
	}

	size += proto.BytesSize(splitInfoSplitIDField, s.splitID)
	size += proto.NestedStructureSize(splitInfoLastPartField, s.lastPart)
	size += proto.NestedStructureSize(splitInfoLinkField, s.link)

	return size
}

func (s *SplitInfo) Unmarshal(data []byte) error {
	return message.Unmarshal(s, data, new(object.SplitInfo))
}

func (r *GetRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(getReqBodyAddressField, buf[offset:], r.addr)
	proto.BoolMarshal(getReqBodyRawFlagField, buf[offset:], r.raw)

	return buf
}

func (r *GetRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(getReqBodyAddressField, r.addr)
	size += proto.BoolSize(getReqBodyRawFlagField, r.raw)

	return size
}

func (r *GetRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.GetRequest_Body))
}

func (r *GetObjectPartInit) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(getRespInitObjectIDField, buf[offset:], r.id)
	offset += proto.NestedStructureMarshal(getRespInitSignatureField, buf[offset:], r.sig)
	proto.NestedStructureMarshal(getRespInitHeaderField, buf[offset:], r.hdr)

	return buf
}

func (r *GetObjectPartInit) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(getRespInitObjectIDField, r.id)
	size += proto.NestedStructureSize(getRespInitSignatureField, r.sig)
	size += proto.NestedStructureSize(getRespInitHeaderField, r.hdr)

	return size
}

func (r *GetObjectPartInit) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.GetResponse_Body_Init))
}

func (r *GetResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	switch v := r.objPart.(type) {
	case nil:
	case *GetObjectPartInit:
		proto.NestedStructureMarshal(getRespBodyInitField, buf, v)
	case *GetObjectPartChunk:
		if v != nil {
			proto.BytesMarshal(getRespBodyChunkField, buf, v.chunk)
		}
	case *SplitInfo:
		proto.NestedStructureMarshal(getRespBodySplitInfoField, buf, v)
	default:
		panic("unknown one of object get response body type")
	}

	return buf
}

func (r *GetResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	switch v := r.objPart.(type) {
	case nil:
	case *GetObjectPartInit:
		size += proto.NestedStructureSize(getRespBodyInitField, v)
	case *GetObjectPartChunk:
		if v != nil {
			size += proto.BytesSize(getRespBodyChunkField, v.chunk)
		}
	case *SplitInfo:
		size += proto.NestedStructureSize(getRespBodySplitInfoField, v)
	default:
		panic("unknown one of object get response body type")
	}

	return
}

func (r *GetResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.GetResponse_Body))
}

func (r *PutObjectPartInit) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(putReqInitObjectIDField, buf[offset:], r.id)
	offset += proto.NestedStructureMarshal(putReqInitSignatureField, buf[offset:], r.sig)
	offset += proto.NestedStructureMarshal(putReqInitHeaderField, buf[offset:], r.hdr)
	proto.UInt32Marshal(putReqInitCopiesNumField, buf[offset:], r.copyNum)

	return buf
}

func (r *PutObjectPartInit) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(putReqInitObjectIDField, r.id)
	size += proto.NestedStructureSize(putReqInitSignatureField, r.sig)
	size += proto.NestedStructureSize(putReqInitHeaderField, r.hdr)
	size += proto.UInt32Size(putReqInitCopiesNumField, r.copyNum)

	return size
}

func (r *PutObjectPartInit) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.PutRequest_Body_Init))
}

func (r *PutRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	switch v := r.objPart.(type) {
	case nil:
	case *PutObjectPartInit:
		proto.NestedStructureMarshal(putReqBodyInitField, buf, v)
	case *PutObjectPartChunk:
		if v != nil {
			proto.BytesMarshal(putReqBodyChunkField, buf, v.chunk)
		}
	default:
		panic("unknown one of object put request body type")
	}

	return buf
}

func (r *PutRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	switch v := r.objPart.(type) {
	case nil:
	case *PutObjectPartInit:
		size += proto.NestedStructureSize(putReqBodyInitField, v)
	case *PutObjectPartChunk:
		if v != nil {
			size += proto.BytesSize(putReqBodyChunkField, v.chunk)
		}
	default:
		panic("unknown one of object get response body type")
	}

	return size
}

func (r *PutRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.PutRequest_Body))
}

func (r *PutResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	proto.NestedStructureMarshal(putRespBodyObjectIDField, buf, r.id)

	return buf
}

func (r *PutResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(putRespBodyObjectIDField, r.id)

	return size
}

func (r *PutResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.PutResponse_Body))
}

func (r *DeleteRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	proto.NestedStructureMarshal(deleteReqBodyAddressField, buf, r.addr)

	return buf
}

func (r *DeleteRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(deleteReqBodyAddressField, r.addr)

	return size
}

func (r *DeleteRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.DeleteRequest_Body))
}

func (r *DeleteResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	proto.NestedStructureMarshal(deleteRespBodyTombstoneFNum, buf, r.tombstone)

	return buf
}

func (r *DeleteResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(deleteRespBodyTombstoneFNum, r.tombstone)

	return size
}

func (r *DeleteResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.DeleteResponse_Body))
}

func (r *HeadRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(headReqBodyAddressField, buf[offset:], r.addr)
	offset += proto.BoolMarshal(headReqBodyMainFlagField, buf[offset:], r.mainOnly)
	proto.BoolMarshal(headReqBodyRawFlagField, buf[offset:], r.raw)

	return buf
}

func (r *HeadRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(headReqBodyAddressField, r.addr)
	size += proto.BoolSize(headReqBodyMainFlagField, r.mainOnly)
	size += proto.BoolSize(headReqBodyRawFlagField, r.raw)

	return size
}

func (r *HeadRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.HeadRequest_Body))
}

func (r *HeadResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	switch v := r.hdrPart.(type) {
	case nil:
	case *HeaderWithSignature:
		if v != nil {
			proto.NestedStructureMarshal(headRespBodyHeaderField, buf, v)
		}
	case *ShortHeader:
		if v != nil {
			proto.NestedStructureMarshal(headRespBodyShortHeaderField, buf, v)
		}
	case *SplitInfo:
		if v != nil {
			proto.NestedStructureMarshal(headRespBodySplitInfoField, buf, v)
		}
	default:
		panic("unknown one of object put request body type")
	}

	return buf
}

func (r *HeadResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	switch v := r.hdrPart.(type) {
	case nil:
	case *HeaderWithSignature:
		if v != nil {
			size += proto.NestedStructureSize(headRespBodyHeaderField, v)
		}
	case *ShortHeader:
		if v != nil {
			size += proto.NestedStructureSize(headRespBodyShortHeaderField, v)
		}
	case *SplitInfo:
		if v != nil {
			size += proto.NestedStructureSize(headRespBodySplitInfoField, v)
		}
	default:
		panic("unknown one of object put request body type")
	}

	return
}

func (r *HeadResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.HeadResponse_Body))
}

func (f *SearchFilter) StableMarshal(buf []byte) []byte {
	if f == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, f.StableSize())
	}

	var offset int

	offset += proto.EnumMarshal(searchFilterMatchField, buf[offset:], int32(f.matchType))
	offset += proto.StringMarshal(searchFilterNameField, buf[offset:], f.key)
	proto.StringMarshal(searchFilterValueField, buf[offset:], f.val)

	return buf
}

func (f *SearchFilter) StableSize() (size int) {
	if f == nil {
		return 0
	}

	size += proto.EnumSize(searchFilterMatchField, int32(f.matchType))
	size += proto.StringSize(searchFilterNameField, f.key)
	size += proto.StringSize(searchFilterValueField, f.val)

	return size
}

func (f *SearchFilter) Unmarshal(data []byte) error {
	return message.Unmarshal(f, data, new(object.SearchRequest_Body_Filter))
}

func (r *SearchRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(searchReqBodyContainerIDField, buf[offset:], r.cid)
	offset += proto.UInt32Marshal(searchReqBodyVersionField, buf[offset:], r.version)

	for i := range r.filters {
		offset += proto.NestedStructureMarshal(searchReqBodyFiltersField, buf[offset:], &r.filters[i])
	}

	return buf
}

func (r *SearchRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(searchReqBodyContainerIDField, r.cid)
	size += proto.UInt32Size(searchReqBodyVersionField, r.version)

	for i := range r.filters {
		size += proto.NestedStructureSize(searchReqBodyFiltersField, &r.filters[i])
	}

	return size
}

func (r *SearchRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.SearchRequest_Body))
}

func (r *SearchResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	refs.ObjectIDNestedListMarshal(searchRespBodyObjectIDsField, buf[offset:], r.idList)

	return buf
}

func (r *SearchResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += refs.ObjectIDNestedListSize(searchRespBodyObjectIDsField, r.idList)

	return size
}

func (r *SearchResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.SearchResponse_Body))
}

func (r *Range) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.UInt64Marshal(rangeOffsetField, buf[offset:], r.off)
	proto.UInt64Marshal(rangeLengthField, buf[offset:], r.len)

	return buf
}

func (r *Range) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.UInt64Size(rangeOffsetField, r.off)
	size += proto.UInt64Size(rangeLengthField, r.len)

	return size
}

func (r *Range) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.Range))
}

func (r *GetRangeRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(getRangeReqBodyAddressField, buf[offset:], r.addr)
	offset += proto.NestedStructureMarshal(getRangeReqBodyRangeField, buf[offset:], r.rng)
	proto.BoolMarshal(getRangeReqBodyRawField, buf[offset:], r.raw)

	return buf
}

func (r *GetRangeRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(getRangeReqBodyAddressField, r.addr)
	size += proto.NestedStructureSize(getRangeReqBodyRangeField, r.rng)
	size += proto.BoolSize(getRangeReqBodyRawField, r.raw)

	return size
}

func (r *GetRangeRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.GetRangeRequest_Body))
}

func (r *GetRangeResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	switch v := r.rngPart.(type) {
	case nil:
	case *GetRangePartChunk:
		if v != nil {
			proto.BytesMarshal(getRangeRespChunkField, buf, v.chunk)
		}
	case *SplitInfo:
		if v != nil {
			proto.NestedStructureMarshal(getRangeRespSplitInfoField, buf, v)
		}
	default:
		panic("unknown one of object get range request body type")
	}

	return buf
}

func (r *GetRangeResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	switch v := r.rngPart.(type) {
	case nil:
	case *GetRangePartChunk:
		if v != nil {
			size += proto.BytesSize(getRangeRespChunkField, v.chunk)
		}
	case *SplitInfo:
		if v != nil {
			size = proto.NestedStructureSize(getRangeRespSplitInfoField, v)
		}
	default:
		panic("unknown one of object get range request body type")
	}

	return
}

func (r *GetRangeResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.GetRangeResponse_Body))
}

func (r *GetRangeHashRequestBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(getRangeHashReqBodyAddressField, buf[offset:], r.addr)

	for i := range r.rngs {
		offset += proto.NestedStructureMarshal(getRangeHashReqBodyRangesField, buf[offset:], &r.rngs[i])
	}

	offset += proto.BytesMarshal(getRangeHashReqBodySaltField, buf[offset:], r.salt)
	proto.EnumMarshal(getRangeHashReqBodyTypeField, buf[offset:], int32(r.typ))

	return buf
}

func (r *GetRangeHashRequestBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(getRangeHashReqBodyAddressField, r.addr)

	for i := range r.rngs {
		size += proto.NestedStructureSize(getRangeHashReqBodyRangesField, &r.rngs[i])
	}

	size += proto.BytesSize(getRangeHashReqBodySaltField, r.salt)
	size += proto.EnumSize(getRangeHashReqBodyTypeField, int32(r.typ))

	return size
}

func (r *GetRangeHashRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.GetRangeHashRequest_Body))
}

func (r *GetRangeHashResponseBody) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.EnumMarshal(getRangeHashRespBodyTypeField, buf, int32(r.typ))
	proto.RepeatedBytesMarshal(getRangeHashRespBodyHashListField, buf[offset:], r.hashList)

	return buf
}

func (r *GetRangeHashResponseBody) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.EnumSize(getRangeHashRespBodyTypeField, int32(r.typ))
	size += proto.RepeatedBytesSize(getRangeHashRespBodyHashListField, r.hashList)

	return size
}

func (r *GetRangeHashResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(object.GetRangeHashResponse_Body))
}
