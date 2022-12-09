package object

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
)

type Type uint32

type MatchType uint32

type ShortHeader struct {
	version *refs.Version

	creatEpoch uint64

	ownerID *refs.OwnerID

	typ Type

	payloadLen uint64

	payloadHash, homoHash *refs.Checksum
}

type Attribute struct {
	key, val string
}

type SplitHeader struct {
	par, prev *refs.ObjectID

	parSig *refs.Signature

	parHdr *Header

	children []refs.ObjectID

	splitID []byte
}

type Header struct {
	version *refs.Version

	cid *refs.ContainerID

	ownerID *refs.OwnerID

	creatEpoch uint64

	payloadLen uint64

	payloadHash, homoHash *refs.Checksum

	typ Type

	sessionToken *session.Token

	attr []Attribute

	split *SplitHeader
}

type HeaderWithSignature struct {
	header *Header

	signature *refs.Signature
}

type Object struct {
	objectID *refs.ObjectID

	idSig *refs.Signature

	header *Header

	payload []byte
}

type SplitInfo struct {
	splitID []byte

	lastPart *refs.ObjectID

	link *refs.ObjectID
}

type GetRequestBody struct {
	addr *refs.Address

	raw bool
}

type GetObjectPart interface {
	getObjectPart()
}

type GetObjectPartInit struct {
	id *refs.ObjectID

	sig *refs.Signature

	hdr *Header
}

type GetObjectPartChunk struct {
	chunk []byte
}

type GetRequest struct {
	body *GetRequestBody

	session.RequestHeaders
}

type GetResponseBody struct {
	objPart GetObjectPart
}

type PutObjectPart interface {
	putObjectPart()
}

type PutObjectPartInit struct {
	id *refs.ObjectID

	sig *refs.Signature

	hdr *Header

	copyNum uint32
}

type PutObjectPartChunk struct {
	chunk []byte
}

type GetResponse struct {
	body *GetResponseBody

	session.ResponseHeaders
}

type PutRequestBody struct {
	objPart PutObjectPart
}

type PutRequest struct {
	body *PutRequestBody

	session.RequestHeaders
}

type PutResponseBody struct {
	id *refs.ObjectID
}

type PutResponse struct {
	body *PutResponseBody

	session.ResponseHeaders
}

type DeleteRequestBody struct {
	addr *refs.Address
}

type DeleteRequest struct {
	body *DeleteRequestBody

	session.RequestHeaders
}

type DeleteResponseBody struct {
	tombstone *refs.Address
}

type DeleteResponse struct {
	body *DeleteResponseBody

	session.ResponseHeaders
}

type HeadRequestBody struct {
	addr *refs.Address

	mainOnly, raw bool
}

type GetHeaderPart interface {
	getHeaderPart()
}

type HeadRequest struct {
	body *HeadRequestBody

	session.RequestHeaders
}

type HeadResponseBody struct {
	hdrPart GetHeaderPart
}

type HeadResponse struct {
	body *HeadResponseBody

	session.ResponseHeaders
}

type SearchFilter struct {
	matchType MatchType

	key, val string
}

type SearchRequestBody struct {
	cid *refs.ContainerID

	version uint32

	filters []SearchFilter
}

type SearchRequest struct {
	body *SearchRequestBody

	session.RequestHeaders
}

type SearchResponseBody struct {
	idList []refs.ObjectID
}

type SearchResponse struct {
	body *SearchResponseBody

	session.ResponseHeaders
}

type Range struct {
	off, len uint64
}

type GetRangeRequestBody struct {
	addr *refs.Address

	rng *Range

	raw bool
}

type GetRangeRequest struct {
	body *GetRangeRequestBody

	session.RequestHeaders
}

type GetRangePart interface {
	getRangePart()
}

type GetRangePartChunk struct {
	chunk []byte
}

type GetRangeResponseBody struct {
	rngPart GetRangePart
}

type GetRangeResponse struct {
	body *GetRangeResponseBody

	session.ResponseHeaders
}

type GetRangeHashRequestBody struct {
	addr *refs.Address

	rngs []Range

	salt []byte

	typ refs.ChecksumType
}

type GetRangeHashRequest struct {
	body *GetRangeHashRequestBody

	session.RequestHeaders
}

type GetRangeHashResponseBody struct {
	typ refs.ChecksumType

	hashList [][]byte
}

type GetRangeHashResponse struct {
	body *GetRangeHashResponseBody

	session.ResponseHeaders
}

const (
	TypeRegular Type = iota
	TypeTombstone
	TypeStorageGroup
	TypeLock
)

const (
	MatchUnknown MatchType = iota
	MatchStringEqual
	MatchStringNotEqual
	MatchNotPresent
	MatchCommonPrefix
)

func (h *ShortHeader) GetVersion() *refs.Version {
	if h != nil {
		return h.version
	}

	return nil
}

func (h *ShortHeader) SetVersion(v *refs.Version) {
	h.version = v
}

func (h *ShortHeader) GetCreationEpoch() uint64 {
	if h != nil {
		return h.creatEpoch
	}

	return 0
}

func (h *ShortHeader) SetCreationEpoch(v uint64) {
	h.creatEpoch = v
}

func (h *ShortHeader) GetOwnerID() *refs.OwnerID {
	if h != nil {
		return h.ownerID
	}

	return nil
}

func (h *ShortHeader) SetOwnerID(v *refs.OwnerID) {
	h.ownerID = v
}

func (h *ShortHeader) GetObjectType() Type {
	if h != nil {
		return h.typ
	}

	return TypeRegular
}

func (h *ShortHeader) SetObjectType(v Type) {
	h.typ = v
}

func (h *ShortHeader) GetPayloadLength() uint64 {
	if h != nil {
		return h.payloadLen
	}

	return 0
}

func (h *ShortHeader) SetPayloadLength(v uint64) {
	h.payloadLen = v
}

func (h *ShortHeader) GetPayloadHash() *refs.Checksum {
	if h != nil {
		return h.payloadHash
	}

	return nil
}

func (h *ShortHeader) SetPayloadHash(v *refs.Checksum) {
	h.payloadHash = v
}

func (h *ShortHeader) GetHomomorphicHash() *refs.Checksum {
	if h != nil {
		return h.homoHash
	}

	return nil
}

func (h *ShortHeader) SetHomomorphicHash(v *refs.Checksum) {
	h.homoHash = v
}

func (h *ShortHeader) getHeaderPart() {}

func (a *Attribute) GetKey() string {
	if a != nil {
		return a.key
	}

	return ""
}

func (a *Attribute) SetKey(v string) {
	a.key = v
}

func (a *Attribute) GetValue() string {
	if a != nil {
		return a.val
	}

	return ""
}

func (a *Attribute) SetValue(v string) {
	a.val = v
}

func (h *SplitHeader) GetParent() *refs.ObjectID {
	if h != nil {
		return h.par
	}

	return nil
}

func (h *SplitHeader) SetParent(v *refs.ObjectID) {
	h.par = v
}

func (h *SplitHeader) GetPrevious() *refs.ObjectID {
	if h != nil {
		return h.prev
	}

	return nil
}

func (h *SplitHeader) SetPrevious(v *refs.ObjectID) {
	h.prev = v
}

func (h *SplitHeader) GetParentSignature() *refs.Signature {
	if h != nil {
		return h.parSig
	}

	return nil
}

func (h *SplitHeader) SetParentSignature(v *refs.Signature) {
	h.parSig = v
}

func (h *SplitHeader) GetParentHeader() *Header {
	if h != nil {
		return h.parHdr
	}

	return nil
}

func (h *SplitHeader) SetParentHeader(v *Header) {
	h.parHdr = v
}

func (h *SplitHeader) GetChildren() []refs.ObjectID {
	if h != nil {
		return h.children
	}

	return nil
}

func (h *SplitHeader) SetChildren(v []refs.ObjectID) {
	h.children = v
}

func (h *SplitHeader) GetSplitID() []byte {
	if h != nil {
		return h.splitID
	}

	return nil
}

func (h *SplitHeader) SetSplitID(v []byte) {
	h.splitID = v
}

func (h *Header) GetVersion() *refs.Version {
	if h != nil {
		return h.version
	}

	return nil
}

func (h *Header) SetVersion(v *refs.Version) {
	h.version = v
}

func (h *Header) GetContainerID() *refs.ContainerID {
	if h != nil {
		return h.cid
	}

	return nil
}

func (h *Header) SetContainerID(v *refs.ContainerID) {
	h.cid = v
}

func (h *Header) GetOwnerID() *refs.OwnerID {
	if h != nil {
		return h.ownerID
	}

	return nil
}

func (h *Header) SetOwnerID(v *refs.OwnerID) {
	h.ownerID = v
}

func (h *Header) GetCreationEpoch() uint64 {
	if h != nil {
		return h.creatEpoch
	}

	return 0
}

func (h *Header) SetCreationEpoch(v uint64) {
	h.creatEpoch = v
}

func (h *Header) GetPayloadLength() uint64 {
	if h != nil {
		return h.payloadLen
	}

	return 0
}

func (h *Header) SetPayloadLength(v uint64) {
	h.payloadLen = v
}

func (h *Header) GetPayloadHash() *refs.Checksum {
	if h != nil {
		return h.payloadHash
	}

	return nil
}

func (h *Header) SetPayloadHash(v *refs.Checksum) {
	h.payloadHash = v
}

func (h *Header) GetObjectType() Type {
	if h != nil {
		return h.typ
	}

	return TypeRegular
}

func (h *Header) SetObjectType(v Type) {
	h.typ = v
}

func (h *Header) GetHomomorphicHash() *refs.Checksum {
	if h != nil {
		return h.homoHash
	}

	return nil
}

func (h *Header) SetHomomorphicHash(v *refs.Checksum) {
	h.homoHash = v
}

func (h *Header) GetSessionToken() *session.Token {
	if h != nil {
		return h.sessionToken
	}

	return nil
}

func (h *Header) SetSessionToken(v *session.Token) {
	h.sessionToken = v
}

func (h *Header) GetAttributes() []Attribute {
	if h != nil {
		return h.attr
	}

	return nil
}

func (h *Header) SetAttributes(v []Attribute) {
	h.attr = v
}

func (h *Header) GetSplit() *SplitHeader {
	if h != nil {
		return h.split
	}

	return nil
}

func (h *Header) SetSplit(v *SplitHeader) {
	h.split = v
}

func (h *HeaderWithSignature) GetHeader() *Header {
	if h != nil {
		return h.header
	}

	return nil
}

func (h *HeaderWithSignature) SetHeader(v *Header) {
	h.header = v
}

func (h *HeaderWithSignature) GetSignature() *refs.Signature {
	if h != nil {
		return h.signature
	}

	return nil
}

func (h *HeaderWithSignature) SetSignature(v *refs.Signature) {
	h.signature = v
}

func (h *HeaderWithSignature) getHeaderPart() {}

func (o *Object) GetObjectID() *refs.ObjectID {
	if o != nil {
		return o.objectID
	}

	return nil
}

func (o *Object) SetObjectID(v *refs.ObjectID) {
	o.objectID = v
}

func (o *Object) GetSignature() *refs.Signature {
	if o != nil {
		return o.idSig
	}

	return nil
}

func (o *Object) SetSignature(v *refs.Signature) {
	o.idSig = v
}

func (o *Object) GetHeader() *Header {
	if o != nil {
		return o.header
	}

	return nil
}

func (o *Object) SetHeader(v *Header) {
	o.header = v
}

func (o *Object) GetPayload() []byte {
	if o != nil {
		return o.payload
	}

	return nil
}

func (o *Object) SetPayload(v []byte) {
	o.payload = v
}

func (s *SplitInfo) GetSplitID() []byte {
	if s != nil {
		return s.splitID
	}

	return nil
}

func (s *SplitInfo) SetSplitID(v []byte) {
	s.splitID = v
}

func (s *SplitInfo) GetLastPart() *refs.ObjectID {
	if s != nil {
		return s.lastPart
	}

	return nil
}

func (s *SplitInfo) SetLastPart(v *refs.ObjectID) {
	s.lastPart = v
}

func (s *SplitInfo) GetLink() *refs.ObjectID {
	if s != nil {
		return s.link
	}

	return nil
}

func (s *SplitInfo) SetLink(v *refs.ObjectID) {
	s.link = v
}

func (s *SplitInfo) getObjectPart() {}

func (s *SplitInfo) getHeaderPart() {}

func (s *SplitInfo) getRangePart() {}

func (r *GetRequestBody) GetAddress() *refs.Address {
	if r != nil {
		return r.addr
	}

	return nil
}

func (r *GetRequestBody) SetAddress(v *refs.Address) {
	r.addr = v
}

func (r *GetRequestBody) GetRaw() bool {
	if r != nil {
		return r.raw
	}

	return false
}

func (r *GetRequestBody) SetRaw(v bool) {
	r.raw = v
}

func (r *GetRequest) GetBody() *GetRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetRequest) SetBody(v *GetRequestBody) {
	r.body = v
}

func (r *GetObjectPartInit) GetObjectID() *refs.ObjectID {
	if r != nil {
		return r.id
	}

	return nil
}

func (r *GetObjectPartInit) SetObjectID(v *refs.ObjectID) {
	r.id = v
}

func (r *GetObjectPartInit) GetSignature() *refs.Signature {
	if r != nil {
		return r.sig
	}

	return nil
}

func (r *GetObjectPartInit) SetSignature(v *refs.Signature) {
	r.sig = v
}

func (r *GetObjectPartInit) GetHeader() *Header {
	if r != nil {
		return r.hdr
	}

	return nil
}

func (r *GetObjectPartInit) SetHeader(v *Header) {
	r.hdr = v
}

func (r *GetObjectPartInit) getObjectPart() {}

func (r *GetObjectPartChunk) GetChunk() []byte {
	if r != nil {
		return r.chunk
	}

	return nil
}

func (r *GetObjectPartChunk) SetChunk(v []byte) {
	r.chunk = v
}

func (r *GetObjectPartChunk) getObjectPart() {}

func (r *GetResponseBody) GetObjectPart() GetObjectPart {
	if r != nil {
		return r.objPart
	}

	return nil
}

func (r *GetResponseBody) SetObjectPart(v GetObjectPart) {
	r.objPart = v
}

func (r *GetResponse) GetBody() *GetResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetResponse) SetBody(v *GetResponseBody) {
	r.body = v
}

func (r *PutObjectPartInit) GetObjectID() *refs.ObjectID {
	if r != nil {
		return r.id
	}

	return nil
}

func (r *PutObjectPartInit) SetObjectID(v *refs.ObjectID) {
	r.id = v
}

func (r *PutObjectPartInit) GetSignature() *refs.Signature {
	if r != nil {
		return r.sig
	}

	return nil
}

func (r *PutObjectPartInit) SetSignature(v *refs.Signature) {
	r.sig = v
}

func (r *PutObjectPartInit) GetHeader() *Header {
	if r != nil {
		return r.hdr
	}

	return nil
}

func (r *PutObjectPartInit) SetHeader(v *Header) {
	r.hdr = v
}

func (r *PutObjectPartInit) GetCopiesNumber() uint32 {
	if r != nil {
		return r.copyNum
	}

	return 0
}

func (r *PutObjectPartInit) SetCopiesNumber(v uint32) {
	r.copyNum = v
}

func (r *PutObjectPartInit) putObjectPart() {}

func (r *PutObjectPartChunk) GetChunk() []byte {
	if r != nil {
		return r.chunk
	}

	return nil
}

func (r *PutObjectPartChunk) SetChunk(v []byte) {
	r.chunk = v
}

func (r *PutObjectPartChunk) putObjectPart() {}

func (r *PutRequestBody) GetObjectPart() PutObjectPart {
	if r != nil {
		return r.objPart
	}

	return nil
}

func (r *PutRequestBody) SetObjectPart(v PutObjectPart) {
	r.objPart = v
}

func (r *PutRequest) GetBody() *PutRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *PutRequest) SetBody(v *PutRequestBody) {
	r.body = v
}

func (r *PutResponseBody) GetObjectID() *refs.ObjectID {
	if r != nil {
		return r.id
	}

	return nil
}

func (r *PutResponseBody) SetObjectID(v *refs.ObjectID) {
	r.id = v
}

func (r *PutResponse) GetBody() *PutResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *PutResponse) SetBody(v *PutResponseBody) {
	r.body = v
}

func (r *DeleteRequestBody) GetAddress() *refs.Address {
	if r != nil {
		return r.addr
	}

	return nil
}

func (r *DeleteRequestBody) SetAddress(v *refs.Address) {
	r.addr = v
}

func (r *DeleteRequest) GetBody() *DeleteRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *DeleteRequest) SetBody(v *DeleteRequestBody) {
	r.body = v
}

// GetTombstone returns tombstone address.
func (r *DeleteResponseBody) GetTombstone() *refs.Address {
	if r != nil {
		return r.tombstone
	}

	return nil
}

// SetTombstone sets tombstone address.
func (r *DeleteResponseBody) SetTombstone(v *refs.Address) {
	r.tombstone = v
}

func (r *DeleteResponse) GetBody() *DeleteResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *DeleteResponse) SetBody(v *DeleteResponseBody) {
	r.body = v
}

func (r *HeadRequestBody) GetAddress() *refs.Address {
	if r != nil {
		return r.addr
	}

	return nil
}

func (r *HeadRequestBody) SetAddress(v *refs.Address) {
	r.addr = v
}

func (r *HeadRequestBody) GetMainOnly() bool {
	if r != nil {
		return r.mainOnly
	}

	return false
}

func (r *HeadRequestBody) SetMainOnly(v bool) {
	r.mainOnly = v
}

func (r *HeadRequestBody) GetRaw() bool {
	if r != nil {
		return r.raw
	}

	return false
}

func (r *HeadRequestBody) SetRaw(v bool) {
	r.raw = v
}

func (r *HeadRequest) GetBody() *HeadRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *HeadRequest) SetBody(v *HeadRequestBody) {
	r.body = v
}

func (r *HeadResponseBody) GetHeaderPart() GetHeaderPart {
	if r != nil {
		return r.hdrPart
	}

	return nil
}

func (r *HeadResponseBody) SetHeaderPart(v GetHeaderPart) {
	r.hdrPart = v
}

func (r *HeadResponse) GetBody() *HeadResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *HeadResponse) SetBody(v *HeadResponseBody) {
	r.body = v
}

func (f *SearchFilter) GetMatchType() MatchType {
	if f != nil {
		return f.matchType
	}

	return MatchUnknown
}

func (f *SearchFilter) SetMatchType(v MatchType) {
	f.matchType = v
}

func (f *SearchFilter) GetKey() string {
	if f != nil {
		return f.key
	}

	return ""
}

func (f *SearchFilter) SetKey(v string) {
	f.key = v
}

func (f *SearchFilter) GetValue() string {
	if f != nil {
		return f.val
	}

	return ""
}

func (f *SearchFilter) SetValue(v string) {
	f.val = v
}

func (r *SearchRequestBody) GetContainerID() *refs.ContainerID {
	if r != nil {
		return r.cid
	}

	return nil
}

func (r *SearchRequestBody) SetContainerID(v *refs.ContainerID) {
	r.cid = v
}

func (r *SearchRequestBody) GetVersion() uint32 {
	if r != nil {
		return r.version
	}

	return 0
}

func (r *SearchRequestBody) SetVersion(v uint32) {
	r.version = v
}

func (r *SearchRequestBody) GetFilters() []SearchFilter {
	if r != nil {
		return r.filters
	}

	return nil
}

func (r *SearchRequestBody) SetFilters(v []SearchFilter) {
	r.filters = v
}

func (r *SearchRequest) GetBody() *SearchRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *SearchRequest) SetBody(v *SearchRequestBody) {
	r.body = v
}

func (r *SearchResponseBody) GetIDList() []refs.ObjectID {
	if r != nil {
		return r.idList
	}

	return nil
}

func (r *SearchResponseBody) SetIDList(v []refs.ObjectID) {
	r.idList = v
}

func (r *SearchResponse) GetBody() *SearchResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *SearchResponse) SetBody(v *SearchResponseBody) {
	r.body = v
}

func (r *Range) GetOffset() uint64 {
	if r != nil {
		return r.off
	}

	return 0
}

func (r *Range) SetOffset(v uint64) {
	r.off = v
}

func (r *Range) GetLength() uint64 {
	if r != nil {
		return r.len
	}

	return 0
}

func (r *Range) SetLength(v uint64) {
	r.len = v
}

func (r *GetRangeRequestBody) GetAddress() *refs.Address {
	if r != nil {
		return r.addr
	}

	return nil
}

func (r *GetRangeRequestBody) SetAddress(v *refs.Address) {
	r.addr = v
}

func (r *GetRangeRequestBody) GetRange() *Range {
	if r != nil {
		return r.rng
	}

	return nil
}

func (r *GetRangeRequestBody) SetRange(v *Range) {
	r.rng = v
}

func (r *GetRangeRequestBody) GetRaw() bool {
	if r != nil {
		return r.raw
	}

	return false
}

func (r *GetRangeRequestBody) SetRaw(v bool) {
	r.raw = v
}

func (r *GetRangeRequest) GetBody() *GetRangeRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetRangeRequest) SetBody(v *GetRangeRequestBody) {
	r.body = v
}

func (r *GetRangePartChunk) GetChunk() []byte {
	if r != nil {
		return r.chunk
	}

	return nil
}

func (r *GetRangePartChunk) SetChunk(v []byte) {
	r.chunk = v
}

func (r *GetRangePartChunk) getRangePart() {}

func (r *GetRangeResponseBody) GetRangePart() GetRangePart {
	if r != nil {
		return r.rngPart
	}

	return nil
}

func (r *GetRangeResponseBody) SetRangePart(v GetRangePart) {
	r.rngPart = v
}

func (r *GetRangeResponse) GetBody() *GetRangeResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetRangeResponse) SetBody(v *GetRangeResponseBody) {
	r.body = v
}

func (r *GetRangeHashRequestBody) GetAddress() *refs.Address {
	if r != nil {
		return r.addr
	}

	return nil
}

func (r *GetRangeHashRequestBody) SetAddress(v *refs.Address) {
	r.addr = v
}

func (r *GetRangeHashRequestBody) GetRanges() []Range {
	if r != nil {
		return r.rngs
	}

	return nil
}

func (r *GetRangeHashRequestBody) SetRanges(v []Range) {
	r.rngs = v
}

func (r *GetRangeHashRequestBody) GetSalt() []byte {
	if r != nil {
		return r.salt
	}

	return nil
}

func (r *GetRangeHashRequestBody) SetSalt(v []byte) {
	r.salt = v
}

func (r *GetRangeHashRequestBody) GetType() refs.ChecksumType {
	if r != nil {
		return r.typ
	}

	return refs.UnknownChecksum
}

func (r *GetRangeHashRequestBody) SetType(v refs.ChecksumType) {
	r.typ = v
}

func (r *GetRangeHashRequest) GetBody() *GetRangeHashRequestBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetRangeHashRequest) SetBody(v *GetRangeHashRequestBody) {
	r.body = v
}

func (r *GetRangeHashResponseBody) GetType() refs.ChecksumType {
	if r != nil {
		return r.typ
	}

	return refs.UnknownChecksum
}

func (r *GetRangeHashResponseBody) SetType(v refs.ChecksumType) {
	r.typ = v
}

func (r *GetRangeHashResponseBody) GetHashList() [][]byte {
	if r != nil {
		return r.hashList
	}

	return nil
}

func (r *GetRangeHashResponseBody) SetHashList(v [][]byte) {
	r.hashList = v
}

func (r *GetRangeHashResponse) GetBody() *GetRangeHashResponseBody {
	if r != nil {
		return r.body
	}

	return nil
}

func (r *GetRangeHashResponse) SetBody(v *GetRangeHashResponseBody) {
	r.body = v
}
