package session

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/acl"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/status"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

type CreateRequestBody struct {
	ownerID *refs.OwnerID

	expiration uint64
}

type CreateRequest struct {
	body *CreateRequestBody

	RequestHeaders
}

type CreateResponseBody struct {
	id []byte

	sessionKey []byte
}

type CreateResponse struct {
	body *CreateResponseBody

	ResponseHeaders
}

type XHeader struct {
	key, val string
}

type TokenLifetime struct {
	exp, nbf, iat uint64
}

type ObjectSessionVerb uint32

type objectSessionContextTarget struct {
	cnr *refs.ContainerID

	objs []refs.ObjectID
}

const (
	_ = iota
	fNumObjectTargetContainer
	fNumObjectTargetObjects
)

func (x objectSessionContextTarget) StableMarshal(buf []byte) []byte {
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	offset := proto.NestedStructureMarshal(fNumObjectTargetContainer, buf, x.cnr)

	for i := range x.objs {
		offset += proto.NestedStructureMarshal(fNumObjectTargetObjects, buf[offset:], &x.objs[i])
	}

	return buf
}

func (x objectSessionContextTarget) StableSize() (size int) {
	size += proto.NestedStructureSize(fNumObjectTargetContainer, x.cnr)

	for i := range x.objs {
		size += proto.NestedStructureSize(fNumObjectTargetObjects, &x.objs[i])
	}

	return size
}

type ObjectSessionContext struct {
	verb ObjectSessionVerb

	cnr *refs.ContainerID

	objs []refs.ObjectID
}

type TokenContext interface {
	sessionTokenContext()
}

// Deprecated: use TokenContext instead.
//
//nolint:revive
type SessionTokenContext = TokenContext

type TokenBody struct {
	id []byte

	ownerID *refs.OwnerID

	lifetime *TokenLifetime

	sessionKey []byte

	ctx TokenContext
}

// Deprecated: use TokenBody instead.
//
//nolint:revive
type SessionTokenBody = TokenBody

type Token struct {
	body *TokenBody

	sig *refs.Signature
}

// Deprecated: use Token instead.
//
//nolint:revive
type SessionToken = Token

type RequestVerificationHeader struct {
	bodySig, metaSig, originSig *refs.Signature

	origin *RequestVerificationHeader
}

type RequestMetaHeader struct {
	version *refs.Version

	ttl uint32

	epoch uint64

	xHeaders []XHeader

	sessionToken *Token

	bearerToken *acl.BearerToken

	origin *RequestMetaHeader

	netMagic uint64
}

type ResponseVerificationHeader struct {
	bodySig, metaSig, originSig *refs.Signature

	origin *ResponseVerificationHeader
}

type ResponseMetaHeader struct {
	version *refs.Version

	ttl uint32

	epoch uint64

	xHeaders []XHeader

	origin *ResponseMetaHeader

	status *status.Status
}

const (
	ObjectVerbUnknown ObjectSessionVerb = iota
	ObjectVerbPut
	ObjectVerbGet
	ObjectVerbHead
	ObjectVerbSearch
	ObjectVerbDelete
	ObjectVerbRange
	ObjectVerbRangeHash
)

func (c *CreateRequestBody) GetOwnerID() *refs.OwnerID {
	if c != nil {
		return c.ownerID
	}

	return nil
}

func (c *CreateRequestBody) SetOwnerID(v *refs.OwnerID) {
	c.ownerID = v
}

func (c *CreateRequestBody) GetExpiration() uint64 {
	if c != nil {
		return c.expiration
	}

	return 0
}

func (c *CreateRequestBody) SetExpiration(v uint64) {
	c.expiration = v
}

func (c *CreateRequest) GetBody() *CreateRequestBody {
	if c != nil {
		return c.body
	}

	return nil
}

func (c *CreateRequest) SetBody(v *CreateRequestBody) {
	c.body = v
}

func (c *CreateRequest) GetMetaHeader() *RequestMetaHeader {
	if c != nil {
		return c.metaHeader
	}

	return nil
}

func (c *CreateRequest) SetMetaHeader(v *RequestMetaHeader) {
	c.metaHeader = v
}

func (c *CreateRequest) GetVerificationHeader() *RequestVerificationHeader {
	if c != nil {
		return c.verifyHeader
	}

	return nil
}

func (c *CreateRequest) SetVerificationHeader(v *RequestVerificationHeader) {
	c.verifyHeader = v
}

func (c *CreateResponseBody) GetID() []byte {
	if c != nil {
		return c.id
	}

	return nil
}

func (c *CreateResponseBody) SetID(v []byte) {
	c.id = v
}

func (c *CreateResponseBody) GetSessionKey() []byte {
	if c != nil {
		return c.sessionKey
	}

	return nil
}

func (c *CreateResponseBody) SetSessionKey(v []byte) {
	c.sessionKey = v
}

func (c *CreateResponse) GetBody() *CreateResponseBody {
	if c != nil {
		return c.body
	}

	return nil
}

func (c *CreateResponse) SetBody(v *CreateResponseBody) {
	c.body = v
}

func (c *CreateResponse) GetMetaHeader() *ResponseMetaHeader {
	if c != nil {
		return c.metaHeader
	}

	return nil
}

func (c *CreateResponse) SetMetaHeader(v *ResponseMetaHeader) {
	c.metaHeader = v
}

func (c *CreateResponse) GetVerificationHeader() *ResponseVerificationHeader {
	if c != nil {
		return c.verifyHeader
	}

	return nil
}

func (c *CreateResponse) SetVerificationHeader(v *ResponseVerificationHeader) {
	c.verifyHeader = v
}

func (x *XHeader) GetKey() string {
	if x != nil {
		return x.key
	}

	return ""
}

func (x *XHeader) SetKey(v string) {
	x.key = v
}

func (x *XHeader) GetValue() string {
	if x != nil {
		return x.val
	}

	return ""
}

func (x *XHeader) SetValue(v string) {
	x.val = v
}

func (r *RequestVerificationHeader) GetBodySignature() *refs.Signature {
	if r != nil {
		return r.bodySig
	}

	return nil
}

func (r *RequestVerificationHeader) SetBodySignature(v *refs.Signature) {
	r.bodySig = v
}

func (r *RequestVerificationHeader) GetMetaSignature() *refs.Signature {
	if r != nil {
		return r.metaSig
	}

	return nil
}

func (r *RequestVerificationHeader) SetMetaSignature(v *refs.Signature) {
	r.metaSig = v
}

func (r *RequestVerificationHeader) GetOriginSignature() *refs.Signature {
	if r != nil {
		return r.originSig
	}

	return nil
}

func (r *RequestVerificationHeader) SetOriginSignature(v *refs.Signature) {
	r.originSig = v
}

func (r *RequestVerificationHeader) GetOrigin() *RequestVerificationHeader {
	if r != nil {
		return r.origin
	}

	return nil
}

func (r *RequestVerificationHeader) SetOrigin(v *RequestVerificationHeader) {
	r.origin = v
}

func (r *RequestMetaHeader) GetVersion() *refs.Version {
	if r != nil {
		return r.version
	}

	return nil
}

func (r *RequestMetaHeader) SetVersion(v *refs.Version) {
	r.version = v
}

func (r *RequestMetaHeader) GetTTL() uint32 {
	if r != nil {
		return r.ttl
	}

	return 0
}

func (r *RequestMetaHeader) SetTTL(v uint32) {
	r.ttl = v
}

func (r *RequestMetaHeader) GetEpoch() uint64 {
	if r != nil {
		return r.epoch
	}

	return 0
}

func (r *RequestMetaHeader) SetEpoch(v uint64) {
	r.epoch = v
}

func (r *RequestMetaHeader) GetXHeaders() []XHeader {
	if r != nil {
		return r.xHeaders
	}

	return nil
}

func (r *RequestMetaHeader) SetXHeaders(v []XHeader) {
	r.xHeaders = v
}

func (r *RequestMetaHeader) GetSessionToken() *Token {
	if r != nil {
		return r.sessionToken
	}

	return nil
}

func (r *RequestMetaHeader) SetSessionToken(v *Token) {
	r.sessionToken = v
}

func (r *RequestMetaHeader) GetBearerToken() *acl.BearerToken {
	if r != nil {
		return r.bearerToken
	}

	return nil
}

func (r *RequestMetaHeader) SetBearerToken(v *acl.BearerToken) {
	r.bearerToken = v
}

func (r *RequestMetaHeader) GetOrigin() *RequestMetaHeader {
	if r != nil {
		return r.origin
	}

	return nil
}

func (r *RequestMetaHeader) SetOrigin(v *RequestMetaHeader) {
	r.origin = v
}

// GetNetworkMagic returns NeoFS network magic.
func (r *RequestMetaHeader) GetNetworkMagic() uint64 {
	if r != nil {
		return r.netMagic
	}

	return 0
}

// SetNetworkMagic sets NeoFS network magic.
func (r *RequestMetaHeader) SetNetworkMagic(v uint64) {
	r.netMagic = v
}

func (l *TokenLifetime) GetExp() uint64 {
	if l != nil {
		return l.exp
	}

	return 0
}

func (l *TokenLifetime) SetExp(v uint64) {
	l.exp = v
}

func (l *TokenLifetime) GetNbf() uint64 {
	if l != nil {
		return l.nbf
	}

	return 0
}

func (l *TokenLifetime) SetNbf(v uint64) {
	l.nbf = v
}

func (l *TokenLifetime) GetIat() uint64 {
	if l != nil {
		return l.iat
	}

	return 0
}

func (l *TokenLifetime) SetIat(v uint64) {
	l.iat = v
}

func (r *ResponseVerificationHeader) GetBodySignature() *refs.Signature {
	if r != nil {
		return r.bodySig
	}

	return nil
}

func (r *ResponseVerificationHeader) SetBodySignature(v *refs.Signature) {
	r.bodySig = v
}

func (r *ResponseVerificationHeader) GetMetaSignature() *refs.Signature {
	if r != nil {
		return r.metaSig
	}

	return nil
}

func (r *ResponseVerificationHeader) SetMetaSignature(v *refs.Signature) {
	r.metaSig = v
}

func (r *ResponseVerificationHeader) GetOriginSignature() *refs.Signature {
	if r != nil {
		return r.originSig
	}

	return nil
}

func (r *ResponseVerificationHeader) SetOriginSignature(v *refs.Signature) {
	r.originSig = v
}

func (r *ResponseVerificationHeader) GetOrigin() *ResponseVerificationHeader {
	if r != nil {
		return r.origin
	}

	return nil
}

func (r *ResponseVerificationHeader) SetOrigin(v *ResponseVerificationHeader) {
	r.origin = v
}

func (r *ResponseMetaHeader) GetVersion() *refs.Version {
	if r != nil {
		return r.version
	}

	return nil
}

func (r *ResponseMetaHeader) SetVersion(v *refs.Version) {
	r.version = v
}

func (r *ResponseMetaHeader) GetTTL() uint32 {
	if r != nil {
		return r.ttl
	}

	return 0
}

func (r *ResponseMetaHeader) SetTTL(v uint32) {
	r.ttl = v
}

func (r *ResponseMetaHeader) GetEpoch() uint64 {
	if r != nil {
		return r.epoch
	}

	return 0
}

func (r *ResponseMetaHeader) SetEpoch(v uint64) {
	r.epoch = v
}

func (r *ResponseMetaHeader) GetXHeaders() []XHeader {
	if r != nil {
		return r.xHeaders
	}

	return nil
}

func (r *ResponseMetaHeader) SetXHeaders(v []XHeader) {
	r.xHeaders = v
}

func (r *ResponseMetaHeader) GetOrigin() *ResponseMetaHeader {
	if r != nil {
		return r.origin
	}

	return nil
}

func (r *ResponseMetaHeader) SetOrigin(v *ResponseMetaHeader) {
	r.origin = v
}

// GetStatus returns response status.
func (r *ResponseMetaHeader) GetStatus() *status.Status {
	if r != nil {
		return r.status
	}

	return nil
}

// SetStatus sets response status.
func (r *ResponseMetaHeader) SetStatus(v *status.Status) {
	r.status = v
}

// SetStatus sets status of the message which can carry ResponseMetaHeader.
//
// Sets status field on the "highest" level of meta headers.
// If meta header is missing in message, it is allocated.
func SetStatus(msg interface {
	GetMetaHeader() *ResponseMetaHeader
	SetMetaHeader(*ResponseMetaHeader)
}, st *status.Status) {
	meta := msg.GetMetaHeader()
	if meta == nil {
		meta = new(ResponseMetaHeader)
		msg.SetMetaHeader(meta)
	}

	meta.SetStatus(st)
}

func (c *ObjectSessionContext) sessionTokenContext() {}

func (c *ObjectSessionContext) GetVerb() ObjectSessionVerb {
	if c != nil {
		return c.verb
	}

	return ObjectVerbUnknown
}

func (c *ObjectSessionContext) SetVerb(v ObjectSessionVerb) {
	c.verb = v
}

func (c *ObjectSessionContext) GetContainer() *refs.ContainerID {
	if c != nil {
		return c.cnr
	}

	return nil
}

func (c *ObjectSessionContext) GetObjects() []refs.ObjectID {
	if c != nil {
		return c.objs
	}

	return nil
}

func (c *ObjectSessionContext) SetTarget(cnr *refs.ContainerID, objs ...refs.ObjectID) {
	c.cnr = cnr
	c.objs = objs
}

func (t *TokenBody) GetID() []byte {
	if t != nil {
		return t.id
	}

	return nil
}

func (t *TokenBody) SetID(v []byte) {
	t.id = v
}

func (t *TokenBody) GetOwnerID() *refs.OwnerID {
	if t != nil {
		return t.ownerID
	}

	return nil
}

func (t *TokenBody) SetOwnerID(v *refs.OwnerID) {
	t.ownerID = v
}

func (t *TokenBody) GetLifetime() *TokenLifetime {
	if t != nil {
		return t.lifetime
	}

	return nil
}

func (t *TokenBody) SetLifetime(v *TokenLifetime) {
	t.lifetime = v
}

func (t *TokenBody) GetSessionKey() []byte {
	if t != nil {
		return t.sessionKey
	}

	return nil
}

func (t *TokenBody) SetSessionKey(v []byte) {
	t.sessionKey = v
}

func (t *TokenBody) GetContext() TokenContext {
	if t != nil {
		return t.ctx
	}

	return nil
}

func (t *TokenBody) SetContext(v TokenContext) {
	t.ctx = v
}

func (t *Token) GetBody() *TokenBody {
	if t != nil {
		return t.body
	}

	return nil
}

func (t *Token) SetBody(v *TokenBody) {
	t.body = v
}

func (t *Token) GetSignature() *refs.Signature {
	if t != nil {
		return t.sig
	}

	return nil
}

func (t *Token) SetSignature(v *refs.Signature) {
	t.sig = v
}

// ContainerSessionVerb represents NeoFS API v2
// session.ContainerSessionContext.Verb enumeration.
type ContainerSessionVerb uint32

const (
	// ContainerVerbUnknown corresponds to VERB_UNSPECIFIED enum value.
	ContainerVerbUnknown ContainerSessionVerb = iota

	// ContainerVerbPut corresponds to PUT enum value.
	ContainerVerbPut

	// ContainerVerbDelete corresponds to DELETE enum value.
	ContainerVerbDelete

	// ContainerVerbSetEACL corresponds to SETEACL enum value.
	ContainerVerbSetEACL
)

// ContainerSessionContext represents structure of the
// NeoFS API v2 session.ContainerSessionContext message.
type ContainerSessionContext struct {
	verb ContainerSessionVerb

	wildcard bool

	cid *refs.ContainerID
}

func (x *ContainerSessionContext) sessionTokenContext() {}

// Verb returns type of request for which the token is issued.
func (x *ContainerSessionContext) Verb() ContainerSessionVerb {
	if x != nil {
		return x.verb
	}

	return ContainerVerbUnknown
}

// SetVerb sets type of request for which the token is issued.
func (x *ContainerSessionContext) SetVerb(v ContainerSessionVerb) {
	x.verb = v
}

// Wildcard returns wildcard flag of the container session.
func (x *ContainerSessionContext) Wildcard() bool {
	if x != nil {
		return x.wildcard
	}

	return false
}

// SetWildcard sets wildcard flag of the container session.
func (x *ContainerSessionContext) SetWildcard(v bool) {
	x.wildcard = v
}

// ContainerID returns identifier of the container related to the session.
func (x *ContainerSessionContext) ContainerID() *refs.ContainerID {
	if x != nil {
		return x.cid
	}

	return nil
}

// SetContainerID sets identifier of the container related to the session.
func (x *ContainerSessionContext) SetContainerID(v *refs.ContainerID) {
	x.cid = v
}
