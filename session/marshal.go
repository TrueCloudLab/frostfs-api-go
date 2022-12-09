package session

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
	goproto "google.golang.org/protobuf/proto"
)

const (
	createReqBodyOwnerField      = 1
	createReqBodyExpirationField = 2

	createRespBodyIDField  = 1
	createRespBodyKeyField = 2

	xheaderKeyField   = 1
	xheaderValueField = 2

	lifetimeExpirationField     = 1
	lifetimeNotValidBeforeField = 2
	lifetimeIssuedAtField       = 3

	objectCtxVerbField   = 1
	objectCtxTargetField = 2

	sessionTokenBodyIDField        = 1
	sessionTokenBodyOwnerField     = 2
	sessionTokenBodyLifetimeField  = 3
	sessionTokenBodyKeyField       = 4
	sessionTokenBodyObjectCtxField = 5
	sessionTokenBodyCnrCtxField    = 6

	sessionTokenBodyField      = 1
	sessionTokenSignatureField = 2

	reqMetaHeaderVersionField      = 1
	reqMetaHeaderEpochField        = 2
	reqMetaHeaderTTLField          = 3
	reqMetaHeaderXHeadersField     = 4
	reqMetaHeaderSessionTokenField = 5
	reqMetaHeaderBearerTokenField  = 6
	reqMetaHeaderOriginField       = 7
	reqMetaHeaderNetMagicField     = 8

	reqVerifHeaderBodySignatureField   = 1
	reqVerifHeaderMetaSignatureField   = 2
	reqVerifHeaderOriginSignatureField = 3
	reqVerifHeaderOriginField          = 4

	respMetaHeaderVersionField  = 1
	respMetaHeaderEpochField    = 2
	respMetaHeaderTTLField      = 3
	respMetaHeaderXHeadersField = 4
	respMetaHeaderOriginField   = 5
	respMetaHeaderStatusField   = 6

	respVerifHeaderBodySignatureField   = 1
	respVerifHeaderMetaSignatureField   = 2
	respVerifHeaderOriginSignatureField = 3
	respVerifHeaderOriginField          = 4
)

func (c *CreateRequestBody) StableMarshal(buf []byte) []byte {
	if c == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, c.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(createReqBodyOwnerField, buf[offset:], c.ownerID)
	proto.UInt64Marshal(createReqBodyExpirationField, buf[offset:], c.expiration)

	return buf
}

func (c *CreateRequestBody) StableSize() (size int) {
	if c == nil {
		return 0
	}

	size += proto.NestedStructureSize(createReqBodyOwnerField, c.ownerID)
	size += proto.UInt64Size(createReqBodyExpirationField, c.expiration)

	return size
}

func (c *CreateRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(c, data, new(session.CreateRequest_Body))
}

func (c *CreateResponseBody) StableMarshal(buf []byte) []byte {
	if c == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, c.StableSize())
	}

	var offset int

	offset += proto.BytesMarshal(createRespBodyIDField, buf[offset:], c.id)
	proto.BytesMarshal(createRespBodyKeyField, buf[offset:], c.sessionKey)

	return buf
}

func (c *CreateResponseBody) StableSize() (size int) {
	if c == nil {
		return 0
	}

	size += proto.BytesSize(createRespBodyIDField, c.id)
	size += proto.BytesSize(createRespBodyKeyField, c.sessionKey)

	return size
}

func (c *CreateResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(c, data, new(session.CreateResponse_Body))
}

func (x *XHeader) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += proto.StringMarshal(xheaderKeyField, buf[offset:], x.key)
	proto.StringMarshal(xheaderValueField, buf[offset:], x.val)

	return buf
}

func (x *XHeader) StableSize() (size int) {
	if x == nil {
		return 0
	}

	size += proto.StringSize(xheaderKeyField, x.key)
	size += proto.StringSize(xheaderValueField, x.val)

	return size
}

func (x *XHeader) Unmarshal(data []byte) error {
	m := new(session.XHeader)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return x.FromGRPCMessage(m)
}

func (l *TokenLifetime) StableMarshal(buf []byte) []byte {
	if l == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, l.StableSize())
	}

	var offset int

	offset += proto.UInt64Marshal(lifetimeExpirationField, buf[offset:], l.exp)
	offset += proto.UInt64Marshal(lifetimeNotValidBeforeField, buf[offset:], l.nbf)
	proto.UInt64Marshal(lifetimeIssuedAtField, buf[offset:], l.iat)

	return buf
}

func (l *TokenLifetime) StableSize() (size int) {
	if l == nil {
		return 0
	}

	size += proto.UInt64Size(lifetimeExpirationField, l.exp)
	size += proto.UInt64Size(lifetimeNotValidBeforeField, l.nbf)
	size += proto.UInt64Size(lifetimeIssuedAtField, l.iat)

	return size
}

func (l *TokenLifetime) Unmarshal(data []byte) error {
	m := new(session.SessionToken_Body_TokenLifetime)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return l.FromGRPCMessage(m)
}

func (c *ObjectSessionContext) StableMarshal(buf []byte) []byte {
	if c == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, c.StableSize())
	}

	offset := proto.EnumMarshal(objectCtxVerbField, buf, int32(c.verb))
	proto.NestedStructureMarshal(objectCtxTargetField, buf[offset:], &objectSessionContextTarget{
		cnr:  c.cnr,
		objs: c.objs,
	})

	return buf
}

func (c *ObjectSessionContext) StableSize() (size int) {
	if c == nil {
		return 0
	}

	size += proto.EnumSize(objectCtxVerbField, int32(c.verb))
	size += proto.NestedStructureSize(objectCtxTargetField, &objectSessionContextTarget{
		cnr:  c.cnr,
		objs: c.objs,
	})

	return size
}

func (c *ObjectSessionContext) Unmarshal(data []byte) error {
	m := new(session.ObjectSessionContext)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return c.FromGRPCMessage(m)
}

const (
	_ = iota
	cnrCtxVerbFNum
	cnrCtxWildcardFNum
	cnrCtxCidFNum
)

func (x *ContainerSessionContext) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += proto.EnumMarshal(cnrCtxVerbFNum, buf[offset:], int32(ContainerSessionVerbToGRPCField(x.verb)))
	offset += proto.BoolMarshal(cnrCtxWildcardFNum, buf[offset:], x.wildcard)
	proto.NestedStructureMarshal(cnrCtxCidFNum, buf[offset:], x.cid)

	return buf
}

func (x *ContainerSessionContext) StableSize() (size int) {
	if x == nil {
		return 0
	}

	size += proto.EnumSize(cnrCtxVerbFNum, int32(ContainerSessionVerbToGRPCField(x.verb)))
	size += proto.BoolSize(cnrCtxWildcardFNum, x.wildcard)
	size += proto.NestedStructureSize(cnrCtxCidFNum, x.cid)

	return size
}

func (x *ContainerSessionContext) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(session.ContainerSessionContext))
}

func (t *TokenBody) StableMarshal(buf []byte) []byte {
	if t == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, t.StableSize())
	}

	var offset int

	offset += proto.BytesMarshal(sessionTokenBodyIDField, buf[offset:], t.id)
	offset += proto.NestedStructureMarshal(sessionTokenBodyOwnerField, buf[offset:], t.ownerID)
	offset += proto.NestedStructureMarshal(sessionTokenBodyLifetimeField, buf[offset:], t.lifetime)
	offset += proto.BytesMarshal(sessionTokenBodyKeyField, buf[offset:], t.sessionKey)

	if t.ctx != nil {
		switch v := t.ctx.(type) {
		case *ObjectSessionContext:
			proto.NestedStructureMarshal(sessionTokenBodyObjectCtxField, buf[offset:], v)
		case *ContainerSessionContext:
			proto.NestedStructureMarshal(sessionTokenBodyCnrCtxField, buf[offset:], v)
		default:
			panic("cannot marshal unknown session token context")
		}
	}

	return buf
}

func (t *TokenBody) StableSize() (size int) {
	if t == nil {
		return 0
	}

	size += proto.BytesSize(sessionTokenBodyIDField, t.id)
	size += proto.NestedStructureSize(sessionTokenBodyOwnerField, t.ownerID)
	size += proto.NestedStructureSize(sessionTokenBodyLifetimeField, t.lifetime)
	size += proto.BytesSize(sessionTokenBodyKeyField, t.sessionKey)

	if t.ctx != nil {
		switch v := t.ctx.(type) {
		case *ObjectSessionContext:
			size += proto.NestedStructureSize(sessionTokenBodyObjectCtxField, v)
		case *ContainerSessionContext:
			size += proto.NestedStructureSize(sessionTokenBodyCnrCtxField, v)
		default:
			panic("cannot marshal unknown session token context")
		}
	}

	return size
}

func (t *TokenBody) Unmarshal(data []byte) error {
	m := new(session.SessionToken_Body)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return t.FromGRPCMessage(m)
}

func (t *Token) StableMarshal(buf []byte) []byte {
	if t == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, t.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(sessionTokenBodyField, buf[offset:], t.body)
	proto.NestedStructureMarshal(sessionTokenSignatureField, buf[offset:], t.sig)

	return buf
}

func (t *Token) StableSize() (size int) {
	if t == nil {
		return 0
	}

	size += proto.NestedStructureSize(sessionTokenBodyField, t.body)
	size += proto.NestedStructureSize(sessionTokenSignatureField, t.sig)

	return size
}

func (t *Token) Unmarshal(data []byte) error {
	m := new(session.SessionToken)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return t.FromGRPCMessage(m)
}

func (r *RequestMetaHeader) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(reqMetaHeaderVersionField, buf[offset:], r.version)
	offset += proto.UInt64Marshal(reqMetaHeaderEpochField, buf[offset:], r.epoch)
	offset += proto.UInt32Marshal(reqMetaHeaderTTLField, buf[offset:], r.ttl)

	for i := range r.xHeaders {
		offset += proto.NestedStructureMarshal(reqMetaHeaderXHeadersField, buf[offset:], &r.xHeaders[i])
	}

	offset += proto.NestedStructureMarshal(reqMetaHeaderSessionTokenField, buf[offset:], r.sessionToken)
	offset += proto.NestedStructureMarshal(reqMetaHeaderBearerTokenField, buf[offset:], r.bearerToken)
	offset += proto.NestedStructureMarshal(reqMetaHeaderOriginField, buf[offset:], r.origin)
	proto.UInt64Marshal(reqMetaHeaderNetMagicField, buf[offset:], r.netMagic)

	return buf
}

func (r *RequestMetaHeader) StableSize() (size int) {
	if r == nil {
		return 0
	}

	if r.version != nil {
		size += proto.NestedStructureSize(reqMetaHeaderVersionField, r.version)
	}

	size += proto.UInt64Size(reqMetaHeaderEpochField, r.epoch)
	size += proto.UInt32Size(reqMetaHeaderTTLField, r.ttl)

	for i := range r.xHeaders {
		size += proto.NestedStructureSize(reqMetaHeaderXHeadersField, &r.xHeaders[i])
	}

	size += proto.NestedStructureSize(reqMetaHeaderSessionTokenField, r.sessionToken)
	size += proto.NestedStructureSize(reqMetaHeaderBearerTokenField, r.bearerToken)
	size += proto.NestedStructureSize(reqMetaHeaderOriginField, r.origin)
	size += proto.UInt64Size(reqMetaHeaderNetMagicField, r.netMagic)

	return size
}

func (r *RequestMetaHeader) Unmarshal(data []byte) error {
	m := new(session.RequestMetaHeader)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return r.FromGRPCMessage(m)
}

func (r *RequestVerificationHeader) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(reqVerifHeaderBodySignatureField, buf[offset:], r.bodySig)
	offset += proto.NestedStructureMarshal(reqVerifHeaderMetaSignatureField, buf[offset:], r.metaSig)
	offset += proto.NestedStructureMarshal(reqVerifHeaderOriginSignatureField, buf[offset:], r.originSig)
	proto.NestedStructureMarshal(reqVerifHeaderOriginField, buf[offset:], r.origin)

	return buf
}

func (r *RequestVerificationHeader) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(reqVerifHeaderBodySignatureField, r.bodySig)
	size += proto.NestedStructureSize(reqVerifHeaderMetaSignatureField, r.metaSig)
	size += proto.NestedStructureSize(reqVerifHeaderOriginSignatureField, r.originSig)
	size += proto.NestedStructureSize(reqVerifHeaderOriginField, r.origin)

	return size
}

func (r *RequestVerificationHeader) Unmarshal(data []byte) error {
	m := new(session.RequestVerificationHeader)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return r.FromGRPCMessage(m)
}

func (r *ResponseMetaHeader) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(respMetaHeaderVersionField, buf[offset:], r.version)
	offset += proto.UInt64Marshal(respMetaHeaderEpochField, buf[offset:], r.epoch)
	offset += proto.UInt32Marshal(respMetaHeaderTTLField, buf[offset:], r.ttl)

	for i := range r.xHeaders {
		offset += proto.NestedStructureMarshal(respMetaHeaderXHeadersField, buf[offset:], &r.xHeaders[i])
	}

	offset += proto.NestedStructureMarshal(respMetaHeaderOriginField, buf[offset:], r.origin)
	proto.NestedStructureMarshal(respMetaHeaderStatusField, buf[offset:], r.status)

	return buf
}

func (r *ResponseMetaHeader) StableSize() (size int) {
	if r == nil {
		return 0
	}

	if r.version != nil {
		size += proto.NestedStructureSize(respMetaHeaderVersionField, r.version)
	}

	size += proto.UInt64Size(respMetaHeaderEpochField, r.epoch)
	size += proto.UInt32Size(respMetaHeaderTTLField, r.ttl)

	for i := range r.xHeaders {
		size += proto.NestedStructureSize(respMetaHeaderXHeadersField, &r.xHeaders[i])
	}

	size += proto.NestedStructureSize(respMetaHeaderOriginField, r.origin)
	size += proto.NestedStructureSize(respMetaHeaderStatusField, r.status)

	return size
}

func (r *ResponseMetaHeader) Unmarshal(data []byte) error {
	m := new(session.ResponseMetaHeader)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return r.FromGRPCMessage(m)
}

func (r *ResponseVerificationHeader) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += proto.NestedStructureMarshal(respVerifHeaderBodySignatureField, buf[offset:], r.bodySig)
	offset += proto.NestedStructureMarshal(respVerifHeaderMetaSignatureField, buf[offset:], r.metaSig)
	offset += proto.NestedStructureMarshal(respVerifHeaderOriginSignatureField, buf[offset:], r.originSig)
	proto.NestedStructureMarshal(respVerifHeaderOriginField, buf[offset:], r.origin)

	return buf
}

func (r *ResponseVerificationHeader) StableSize() (size int) {
	if r == nil {
		return 0
	}

	size += proto.NestedStructureSize(respVerifHeaderBodySignatureField, r.bodySig)
	size += proto.NestedStructureSize(respVerifHeaderMetaSignatureField, r.metaSig)
	size += proto.NestedStructureSize(respVerifHeaderOriginSignatureField, r.originSig)
	size += proto.NestedStructureSize(respVerifHeaderOriginField, r.origin)

	return size
}

func (r *ResponseVerificationHeader) Unmarshal(data []byte) error {
	m := new(session.ResponseVerificationHeader)
	if err := goproto.Unmarshal(data, m); err != nil {
		return err
	}

	return r.FromGRPCMessage(m)
}
