package object

import (
	"fmt"

	object "github.com/TrueCloudLab/frostfs-api-go/v2/object/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	sessionGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

func TypeToGRPCField(t Type) object.ObjectType {
	return object.ObjectType(t)
}

func TypeFromGRPCField(t object.ObjectType) Type {
	return Type(t)
}

func MatchTypeToGRPCField(t MatchType) object.MatchType {
	return object.MatchType(t)
}

func MatchTypeFromGRPCField(t object.MatchType) MatchType {
	return MatchType(t)
}

func (h *ShortHeader) ToGRPCMessage() grpc.Message {
	var m *object.ShortHeader

	if h != nil {
		m = new(object.ShortHeader)

		m.SetVersion(h.version.ToGRPCMessage().(*refsGRPC.Version))
		m.SetOwnerId(h.ownerID.ToGRPCMessage().(*refsGRPC.OwnerID))
		m.SetHomomorphicHash(h.homoHash.ToGRPCMessage().(*refsGRPC.Checksum))
		m.SetPayloadHash(h.payloadHash.ToGRPCMessage().(*refsGRPC.Checksum))
		m.SetObjectType(TypeToGRPCField(h.typ))
		m.SetCreationEpoch(h.creatEpoch)
		m.SetPayloadLength(h.payloadLen)
	}

	return m
}

func (h *ShortHeader) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.ShortHeader)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	version := v.GetVersion()
	if version == nil {
		h.version = nil
	} else {
		if h.version == nil {
			h.version = new(refs.Version)
		}

		err = h.version.FromGRPCMessage(version)
		if err != nil {
			return err
		}
	}

	ownerID := v.GetOwnerId()
	if ownerID == nil {
		h.ownerID = nil
	} else {
		if h.ownerID == nil {
			h.ownerID = new(refs.OwnerID)
		}

		err = h.ownerID.FromGRPCMessage(ownerID)
		if err != nil {
			return err
		}
	}

	homoHash := v.GetHomomorphicHash()
	if homoHash == nil {
		h.homoHash = nil
	} else {
		if h.homoHash == nil {
			h.homoHash = new(refs.Checksum)
		}

		err = h.homoHash.FromGRPCMessage(homoHash)
		if err != nil {
			return err
		}
	}

	payloadHash := v.GetPayloadHash()
	if payloadHash == nil {
		h.payloadHash = nil
	} else {
		if h.payloadHash == nil {
			h.payloadHash = new(refs.Checksum)
		}

		err = h.payloadHash.FromGRPCMessage(payloadHash)
		if err != nil {
			return err
		}
	}

	h.typ = TypeFromGRPCField(v.GetObjectType())
	h.creatEpoch = v.GetCreationEpoch()
	h.payloadLen = v.GetPayloadLength()

	return nil
}

func (a *Attribute) ToGRPCMessage() grpc.Message {
	var m *object.Header_Attribute

	if a != nil {
		m = new(object.Header_Attribute)

		m.SetKey(a.key)
		m.SetValue(a.val)
	}

	return m
}

func (a *Attribute) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.Header_Attribute)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	a.key = v.GetKey()
	a.val = v.GetValue()

	return nil
}

func AttributesToGRPC(xs []Attribute) (res []*object.Header_Attribute) {
	if xs != nil {
		res = make([]*object.Header_Attribute, 0, len(xs))

		for i := range xs {
			res = append(res, xs[i].ToGRPCMessage().(*object.Header_Attribute))
		}
	}

	return
}

func AttributesFromGRPC(xs []*object.Header_Attribute) (res []Attribute, err error) {
	if xs != nil {
		res = make([]Attribute, len(xs))

		for i := range xs {
			if xs[i] != nil {
				err = res[i].FromGRPCMessage(xs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (h *SplitHeader) ToGRPCMessage() grpc.Message {
	var m *object.Header_Split

	if h != nil {
		m = new(object.Header_Split)

		m.SetParent(h.par.ToGRPCMessage().(*refsGRPC.ObjectID))
		m.SetPrevious(h.prev.ToGRPCMessage().(*refsGRPC.ObjectID))
		m.SetParentHeader(h.parHdr.ToGRPCMessage().(*object.Header))
		m.SetParentSignature(h.parSig.ToGRPCMessage().(*refsGRPC.Signature))
		m.SetChildren(refs.ObjectIDListToGRPCMessage(h.children))
		m.SetSplitId(h.splitID)
	}

	return m
}

func (h *SplitHeader) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.Header_Split)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	par := v.GetParent()
	if par == nil {
		h.par = nil
	} else {
		if h.par == nil {
			h.par = new(refs.ObjectID)
		}

		err = h.par.FromGRPCMessage(par)
		if err != nil {
			return err
		}
	}

	prev := v.GetPrevious()
	if prev == nil {
		h.prev = nil
	} else {
		if h.prev == nil {
			h.prev = new(refs.ObjectID)
		}

		err = h.prev.FromGRPCMessage(prev)
		if err != nil {
			return err
		}
	}

	parHdr := v.GetParentHeader()
	if parHdr == nil {
		h.parHdr = nil
	} else {
		if h.parHdr == nil {
			h.parHdr = new(Header)
		}

		err = h.parHdr.FromGRPCMessage(parHdr)
		if err != nil {
			return err
		}
	}

	parSig := v.GetParentSignature()
	if parSig == nil {
		h.parSig = nil
	} else {
		if h.parSig == nil {
			h.parSig = new(refs.Signature)
		}

		err = h.parSig.FromGRPCMessage(parSig)
		if err != nil {
			return err
		}
	}

	h.children, err = refs.ObjectIDListFromGRPCMessage(v.GetChildren())
	if err != nil {
		return err
	}

	h.splitID = v.GetSplitId()

	return nil
}

func (h *Header) ToGRPCMessage() grpc.Message {
	var m *object.Header

	if h != nil {
		m = new(object.Header)

		m.SetVersion(h.version.ToGRPCMessage().(*refsGRPC.Version))
		m.SetPayloadHash(h.payloadHash.ToGRPCMessage().(*refsGRPC.Checksum))
		m.SetOwnerId(h.ownerID.ToGRPCMessage().(*refsGRPC.OwnerID))
		m.SetHomomorphicHash(h.homoHash.ToGRPCMessage().(*refsGRPC.Checksum))
		m.SetContainerId(h.cid.ToGRPCMessage().(*refsGRPC.ContainerID))
		m.SetSessionToken(h.sessionToken.ToGRPCMessage().(*sessionGRPC.SessionToken))
		m.SetSplit(h.split.ToGRPCMessage().(*object.Header_Split))
		m.SetAttributes(AttributesToGRPC(h.attr))
		m.SetPayloadLength(h.payloadLen)
		m.SetCreationEpoch(h.creatEpoch)
		m.SetObjectType(TypeToGRPCField(h.typ))
	}

	return m
}

func (h *Header) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.Header)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	version := v.GetVersion()
	if version == nil {
		h.version = nil
	} else {
		if h.version == nil {
			h.version = new(refs.Version)
		}

		err = h.version.FromGRPCMessage(version)
		if err != nil {
			return err
		}
	}

	payloadHash := v.GetPayloadHash()
	if payloadHash == nil {
		h.payloadHash = nil
	} else {
		if h.payloadHash == nil {
			h.payloadHash = new(refs.Checksum)
		}

		err = h.payloadHash.FromGRPCMessage(payloadHash)
		if err != nil {
			return err
		}
	}

	ownerID := v.GetOwnerId()
	if ownerID == nil {
		h.ownerID = nil
	} else {
		if h.ownerID == nil {
			h.ownerID = new(refs.OwnerID)
		}

		err = h.ownerID.FromGRPCMessage(ownerID)
		if err != nil {
			return err
		}
	}

	homoHash := v.GetHomomorphicHash()
	if homoHash == nil {
		h.homoHash = nil
	} else {
		if h.homoHash == nil {
			h.homoHash = new(refs.Checksum)
		}

		err = h.homoHash.FromGRPCMessage(homoHash)
		if err != nil {
			return err
		}
	}

	cid := v.GetContainerId()
	if cid == nil {
		h.cid = nil
	} else {
		if h.cid == nil {
			h.cid = new(refs.ContainerID)
		}

		err = h.cid.FromGRPCMessage(cid)
		if err != nil {
			return err
		}
	}

	sessionToken := v.GetSessionToken()
	if sessionToken == nil {
		h.sessionToken = nil
	} else {
		if h.sessionToken == nil {
			h.sessionToken = new(session.Token)
		}

		err = h.sessionToken.FromGRPCMessage(sessionToken)
		if err != nil {
			return err
		}
	}

	split := v.GetSplit()
	if split == nil {
		h.split = nil
	} else {
		if h.split == nil {
			h.split = new(SplitHeader)
		}

		err = h.split.FromGRPCMessage(split)
		if err != nil {
			return err
		}
	}

	h.attr, err = AttributesFromGRPC(v.GetAttributes())
	if err != nil {
		return err
	}

	h.payloadLen = v.GetPayloadLength()
	h.creatEpoch = v.GetCreationEpoch()
	h.typ = TypeFromGRPCField(v.GetObjectType())

	return nil
}

func (h *HeaderWithSignature) ToGRPCMessage() grpc.Message {
	var m *object.HeaderWithSignature

	if h != nil {
		m = new(object.HeaderWithSignature)

		m.SetSignature(h.signature.ToGRPCMessage().(*refsGRPC.Signature))
		m.SetHeader(h.header.ToGRPCMessage().(*object.Header))
	}

	return m
}

func (h *HeaderWithSignature) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.HeaderWithSignature)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	signature := v.GetSignature()
	if signature == nil {
		h.signature = nil
	} else {
		if h.signature == nil {
			h.signature = new(refs.Signature)
		}

		err = h.signature.FromGRPCMessage(signature)
		if err != nil {
			return err
		}
	}

	header := v.GetHeader()
	if header == nil {
		h.header = nil
	} else {
		if h.header == nil {
			h.header = new(Header)
		}

		err = h.header.FromGRPCMessage(header)
	}

	return err
}

func (o *Object) ToGRPCMessage() grpc.Message {
	var m *object.Object

	if o != nil {
		m = new(object.Object)

		m.SetObjectId(o.objectID.ToGRPCMessage().(*refsGRPC.ObjectID))
		m.SetSignature(o.idSig.ToGRPCMessage().(*refsGRPC.Signature))
		m.SetHeader(o.header.ToGRPCMessage().(*object.Header))
		m.SetPayload(o.payload)
	}

	return m
}

func (o *Object) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.Object)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	objectID := v.GetObjectId()
	if objectID == nil {
		o.objectID = nil
	} else {
		if o.objectID == nil {
			o.objectID = new(refs.ObjectID)
		}

		err = o.objectID.FromGRPCMessage(objectID)
		if err != nil {
			return err
		}
	}

	idSig := v.GetSignature()
	if idSig == nil {
		o.idSig = nil
	} else {
		if o.idSig == nil {
			o.idSig = new(refs.Signature)
		}

		err = o.idSig.FromGRPCMessage(idSig)
		if err != nil {
			return err
		}
	}

	header := v.GetHeader()
	if header == nil {
		o.header = nil
	} else {
		if o.header == nil {
			o.header = new(Header)
		}

		err = o.header.FromGRPCMessage(header)
		if err != nil {
			return err
		}
	}

	o.payload = v.GetPayload()

	return nil
}

func (s *SplitInfo) ToGRPCMessage() grpc.Message {
	var m *object.SplitInfo

	if s != nil {
		m = new(object.SplitInfo)

		m.SetLastPart(s.lastPart.ToGRPCMessage().(*refsGRPC.ObjectID))
		m.SetLink(s.link.ToGRPCMessage().(*refsGRPC.ObjectID))
		m.SetSplitId(s.splitID)
	}

	return m
}

func (s *SplitInfo) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.SplitInfo)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	lastPart := v.GetLastPart()
	if lastPart == nil {
		s.lastPart = nil
	} else {
		if s.lastPart == nil {
			s.lastPart = new(refs.ObjectID)
		}

		err = s.lastPart.FromGRPCMessage(lastPart)
		if err != nil {
			return err
		}
	}

	link := v.GetLink()
	if link == nil {
		s.link = nil
	} else {
		if s.link == nil {
			s.link = new(refs.ObjectID)
		}

		err = s.link.FromGRPCMessage(link)
		if err != nil {
			return err
		}
	}

	s.splitID = v.GetSplitId()

	return nil
}

func (r *GetRequestBody) ToGRPCMessage() grpc.Message {
	var m *object.GetRequest_Body

	if r != nil {
		m = new(object.GetRequest_Body)

		m.SetAddress(r.addr.ToGRPCMessage().(*refsGRPC.Address))
		m.SetRaw(r.raw)
	}

	return m
}

func (r *GetRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	addr := v.GetAddress()
	if addr == nil {
		r.addr = nil
	} else {
		if r.addr == nil {
			r.addr = new(refs.Address)
		}

		err = r.addr.FromGRPCMessage(addr)
		if err != nil {
			return err
		}
	}

	r.raw = v.GetRaw()

	return nil
}

func (r *GetRequest) ToGRPCMessage() grpc.Message {
	var m *object.GetRequest

	if r != nil {
		m = new(object.GetRequest)

		m.SetBody(r.body.ToGRPCMessage().(*object.GetRequest_Body))
		r.RequestHeaders.ToMessage(m)
	}

	return m
}

func (r *GetRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(GetRequestBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.RequestHeaders.FromMessage(v)
}

func (r *GetObjectPartInit) ToGRPCMessage() grpc.Message {
	var m *object.GetResponse_Body_Init

	if r != nil {
		m = new(object.GetResponse_Body_Init)

		m.SetObjectId(r.id.ToGRPCMessage().(*refsGRPC.ObjectID))
		m.SetSignature(r.sig.ToGRPCMessage().(*refsGRPC.Signature))
		m.SetHeader(r.hdr.ToGRPCMessage().(*object.Header))
	}

	return m
}

func (r *GetObjectPartInit) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetResponse_Body_Init)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	id := v.GetObjectId()
	if id == nil {
		r.id = nil
	} else {
		if r.id == nil {
			r.id = new(refs.ObjectID)
		}

		err = r.id.FromGRPCMessage(id)
		if err != nil {
			return err
		}
	}

	sig := v.GetSignature()
	if sig == nil {
		r.sig = nil
	} else {
		if r.sig == nil {
			r.sig = new(refs.Signature)
		}

		err = r.sig.FromGRPCMessage(sig)
		if err != nil {
			return err
		}
	}

	hdr := v.GetHeader()
	if hdr == nil {
		r.hdr = nil
	} else {
		if r.hdr == nil {
			r.hdr = new(Header)
		}

		err = r.hdr.FromGRPCMessage(hdr)
	}

	return err
}

func (r *GetObjectPartChunk) ToGRPCMessage() grpc.Message {
	var m *object.GetResponse_Body_Chunk

	if r != nil {
		m = new(object.GetResponse_Body_Chunk)

		m.SetChunk(r.chunk)
	}

	return m
}

func (r *GetObjectPartChunk) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetResponse_Body_Chunk)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	r.chunk = v.GetChunk()

	return nil
}

func (r *GetResponseBody) ToGRPCMessage() grpc.Message {
	var m *object.GetResponse_Body

	if r != nil {
		m = new(object.GetResponse_Body)

		switch v := r.GetObjectPart(); t := v.(type) {
		case nil:
			m.ObjectPart = nil
		case *GetObjectPartInit:
			m.SetInit(t.ToGRPCMessage().(*object.GetResponse_Body_Init))
		case *GetObjectPartChunk:
			m.SetChunk(t.ToGRPCMessage().(*object.GetResponse_Body_Chunk))
		case *SplitInfo:
			m.SetSplitInfo(t.ToGRPCMessage().(*object.SplitInfo))
		default:
			panic(fmt.Sprintf("unknown get object part %T", t))
		}
	}

	return m
}

func (r *GetResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	r.objPart = nil

	switch pt := v.GetObjectPart().(type) {
	case nil:
	case *object.GetResponse_Body_Init_:
		if pt != nil {
			partInit := new(GetObjectPartInit)
			r.objPart = partInit
			err = partInit.FromGRPCMessage(pt.Init)
		}
	case *object.GetResponse_Body_Chunk:
		if pt != nil {
			partChunk := new(GetObjectPartChunk)
			r.objPart = partChunk
			err = partChunk.FromGRPCMessage(pt)
		}
	case *object.GetResponse_Body_SplitInfo:
		if pt != nil {
			partSplit := new(SplitInfo)
			r.objPart = partSplit
			err = partSplit.FromGRPCMessage(pt.SplitInfo)
		}
	default:
		err = fmt.Errorf("unknown get object part %T", pt)
	}

	return err
}

func (r *GetResponse) ToGRPCMessage() grpc.Message {
	var m *object.GetResponse

	if r != nil {
		m = new(object.GetResponse)

		m.SetBody(r.body.ToGRPCMessage().(*object.GetResponse_Body))
		r.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (r *GetResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(GetResponseBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.ResponseHeaders.FromMessage(v)
}

func (r *PutObjectPartInit) ToGRPCMessage() grpc.Message {
	var m *object.PutRequest_Body_Init

	if r != nil {
		m = new(object.PutRequest_Body_Init)

		m.SetObjectId(r.id.ToGRPCMessage().(*refsGRPC.ObjectID))
		m.SetSignature(r.sig.ToGRPCMessage().(*refsGRPC.Signature))
		m.SetHeader(r.hdr.ToGRPCMessage().(*object.Header))
		m.SetCopiesNumber(r.copyNum)
	}

	return m
}

func (r *PutObjectPartInit) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.PutRequest_Body_Init)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	id := v.GetObjectId()
	if id == nil {
		r.id = nil
	} else {
		if r.id == nil {
			r.id = new(refs.ObjectID)
		}

		err = r.id.FromGRPCMessage(id)
		if err != nil {
			return err
		}
	}

	sig := v.GetSignature()
	if sig == nil {
		r.sig = nil
	} else {
		if r.sig == nil {
			r.sig = new(refs.Signature)
		}

		err = r.sig.FromGRPCMessage(sig)
		if err != nil {
			return err
		}
	}

	hdr := v.GetHeader()
	if hdr == nil {
		r.hdr = nil
	} else {
		if r.hdr == nil {
			r.hdr = new(Header)
		}

		err = r.hdr.FromGRPCMessage(hdr)
		if err != nil {
			return err
		}
	}

	r.copyNum = v.GetCopiesNumber()

	return nil
}

func (r *PutObjectPartChunk) ToGRPCMessage() grpc.Message {
	var m *object.PutRequest_Body_Chunk

	if r != nil {
		m = new(object.PutRequest_Body_Chunk)

		m.SetChunk(r.chunk)
	}

	return m
}

func (r *PutObjectPartChunk) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.PutRequest_Body_Chunk)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	r.chunk = v.GetChunk()

	return nil
}

func (r *PutRequestBody) ToGRPCMessage() grpc.Message {
	var m *object.PutRequest_Body

	if r != nil {
		m = new(object.PutRequest_Body)

		switch v := r.GetObjectPart(); t := v.(type) {
		case nil:
			m.ObjectPart = nil
		case *PutObjectPartInit:
			m.SetInit(t.ToGRPCMessage().(*object.PutRequest_Body_Init))
		case *PutObjectPartChunk:
			m.SetChunk(t.ToGRPCMessage().(*object.PutRequest_Body_Chunk))
		default:
			panic(fmt.Sprintf("unknown put object part %T", t))
		}
	}

	return m
}

func (r *PutRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.PutRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	r.objPart = nil

	switch pt := v.GetObjectPart().(type) {
	case nil:
	case *object.PutRequest_Body_Init_:
		if pt != nil {
			partInit := new(PutObjectPartInit)
			r.objPart = partInit
			err = partInit.FromGRPCMessage(pt.Init)
		}
	case *object.PutRequest_Body_Chunk:
		if pt != nil {
			partChunk := new(PutObjectPartChunk)
			r.objPart = partChunk
			err = partChunk.FromGRPCMessage(pt)
		}
	default:
		err = fmt.Errorf("unknown put object part %T", pt)
	}

	return err
}

func (r *PutRequest) ToGRPCMessage() grpc.Message {
	var m *object.PutRequest

	if r != nil {
		m = new(object.PutRequest)

		m.SetBody(r.body.ToGRPCMessage().(*object.PutRequest_Body))
		r.RequestHeaders.ToMessage(m)
	}

	return m
}

func (r *PutRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.PutRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(PutRequestBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.RequestHeaders.FromMessage(v)
}

func (r *PutResponseBody) ToGRPCMessage() grpc.Message {
	var m *object.PutResponse_Body

	if r != nil {
		m = new(object.PutResponse_Body)

		m.SetObjectId(r.id.ToGRPCMessage().(*refsGRPC.ObjectID))
	}

	return m
}

func (r *PutResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.PutResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	id := v.GetObjectId()
	if id == nil {
		r.id = nil
	} else {
		if r.id == nil {
			r.id = new(refs.ObjectID)
		}

		err = r.id.FromGRPCMessage(id)
	}

	return err
}

func (r *PutResponse) ToGRPCMessage() grpc.Message {
	var m *object.PutResponse

	if r != nil {
		m = new(object.PutResponse)

		m.SetBody(r.body.ToGRPCMessage().(*object.PutResponse_Body))
		r.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (r *PutResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.PutResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(PutResponseBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.ResponseHeaders.FromMessage(v)
}

func (r *DeleteRequestBody) ToGRPCMessage() grpc.Message {
	var m *object.DeleteRequest_Body

	if r != nil {
		m = new(object.DeleteRequest_Body)

		m.SetAddress(r.addr.ToGRPCMessage().(*refsGRPC.Address))
	}

	return m
}

func (r *DeleteRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.DeleteRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	addr := v.GetAddress()
	if addr == nil {
		r.addr = nil
	} else {
		if r.addr == nil {
			r.addr = new(refs.Address)
		}

		err = r.addr.FromGRPCMessage(addr)
	}

	return err
}

func (r *DeleteRequest) ToGRPCMessage() grpc.Message {
	var m *object.DeleteRequest

	if r != nil {
		m = new(object.DeleteRequest)

		m.SetBody(r.body.ToGRPCMessage().(*object.DeleteRequest_Body))
		r.RequestHeaders.ToMessage(m)
	}

	return m
}

func (r *DeleteRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.DeleteRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(DeleteRequestBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.RequestHeaders.FromMessage(v)
}

func (r *DeleteResponseBody) ToGRPCMessage() grpc.Message {
	var m *object.DeleteResponse_Body

	if r != nil {
		m = new(object.DeleteResponse_Body)

		m.SetTombstone(r.tombstone.ToGRPCMessage().(*refsGRPC.Address))
	}

	return m
}

func (r *DeleteResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.DeleteResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	tombstone := v.GetTombstone()
	if tombstone == nil {
		r.tombstone = nil
	} else {
		if r.tombstone == nil {
			r.tombstone = new(refs.Address)
		}

		err = r.tombstone.FromGRPCMessage(tombstone)
	}

	return err
}

func (r *DeleteResponse) ToGRPCMessage() grpc.Message {
	var m *object.DeleteResponse

	if r != nil {
		m = new(object.DeleteResponse)

		m.SetBody(r.body.ToGRPCMessage().(*object.DeleteResponse_Body))
		r.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (r *DeleteResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.DeleteResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(DeleteResponseBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.ResponseHeaders.FromMessage(v)
}

func (r *HeadRequestBody) ToGRPCMessage() grpc.Message {
	var m *object.HeadRequest_Body

	if r != nil {
		m = new(object.HeadRequest_Body)

		m.SetAddress(r.addr.ToGRPCMessage().(*refsGRPC.Address))
		m.SetRaw(r.raw)
		m.SetMainOnly(r.mainOnly)
	}

	return m
}

func (r *HeadRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.HeadRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	addr := v.GetAddress()
	if addr == nil {
		r.addr = nil
	} else {
		if r.addr == nil {
			r.addr = new(refs.Address)
		}

		err = r.addr.FromGRPCMessage(addr)
		if err != nil {
			return err
		}
	}

	r.raw = v.GetRaw()
	r.mainOnly = v.GetMainOnly()

	return nil
}

func (r *HeadRequest) ToGRPCMessage() grpc.Message {
	var m *object.HeadRequest

	if r != nil {
		m = new(object.HeadRequest)

		m.SetBody(r.body.ToGRPCMessage().(*object.HeadRequest_Body))
		r.RequestHeaders.ToMessage(m)
	}

	return m
}

func (r *HeadRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.HeadRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(HeadRequestBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.RequestHeaders.FromMessage(v)
}

func (r *HeadResponseBody) ToGRPCMessage() grpc.Message {
	var m *object.HeadResponse_Body

	if r != nil {
		m = new(object.HeadResponse_Body)

		switch v := r.hdrPart.(type) {
		case nil:
			m.Head = nil
		case *HeaderWithSignature:
			m.SetHeader(v.ToGRPCMessage().(*object.HeaderWithSignature))
		case *ShortHeader:
			m.SetShortHeader(v.ToGRPCMessage().(*object.ShortHeader))
		case *SplitInfo:
			m.SetSplitInfo(v.ToGRPCMessage().(*object.SplitInfo))
		default:
			panic(fmt.Sprintf("unknown head part %T", v))
		}
	}

	return m
}

func (r *HeadResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.HeadResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	r.hdrPart = nil

	switch pt := v.GetHead().(type) {
	case nil:
	case *object.HeadResponse_Body_Header:
		if pt != nil {
			partHdr := new(HeaderWithSignature)
			r.hdrPart = partHdr
			err = partHdr.FromGRPCMessage(pt.Header)
		}
	case *object.HeadResponse_Body_ShortHeader:
		if pt != nil {
			partShort := new(ShortHeader)
			r.hdrPart = partShort
			err = partShort.FromGRPCMessage(pt.ShortHeader)
		}
	case *object.HeadResponse_Body_SplitInfo:
		if pt != nil {
			partSplit := new(SplitInfo)
			r.hdrPart = partSplit
			err = partSplit.FromGRPCMessage(pt.SplitInfo)
		}
	default:
		err = fmt.Errorf("unknown head part %T", pt)
	}

	return err
}

func (r *HeadResponse) ToGRPCMessage() grpc.Message {
	var m *object.HeadResponse

	if r != nil {
		m = new(object.HeadResponse)

		m.SetBody(r.body.ToGRPCMessage().(*object.HeadResponse_Body))
		r.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (r *HeadResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.HeadResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(HeadResponseBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.ResponseHeaders.FromMessage(v)
}

func (f *SearchFilter) ToGRPCMessage() grpc.Message {
	var m *object.SearchRequest_Body_Filter

	if f != nil {
		m = new(object.SearchRequest_Body_Filter)

		m.SetKey(f.key)
		m.SetValue(f.val)
		m.SetMatchType(MatchTypeToGRPCField(f.matchType))
	}

	return m
}

func (f *SearchFilter) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.SearchRequest_Body_Filter)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	f.key = v.GetKey()
	f.val = v.GetValue()
	f.matchType = MatchTypeFromGRPCField(v.GetMatchType())

	return nil
}

func SearchFiltersToGRPC(fs []SearchFilter) (res []*object.SearchRequest_Body_Filter) {
	if fs != nil {
		res = make([]*object.SearchRequest_Body_Filter, 0, len(fs))

		for i := range fs {
			res = append(res, fs[i].ToGRPCMessage().(*object.SearchRequest_Body_Filter))
		}
	}

	return
}

func SearchFiltersFromGRPC(fs []*object.SearchRequest_Body_Filter) (res []SearchFilter, err error) {
	if fs != nil {
		res = make([]SearchFilter, len(fs))

		for i := range fs {
			if fs[i] != nil {
				err = res[i].FromGRPCMessage(fs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (r *SearchRequestBody) ToGRPCMessage() grpc.Message {
	var m *object.SearchRequest_Body

	if r != nil {
		m = new(object.SearchRequest_Body)

		m.SetContainerId(r.cid.ToGRPCMessage().(*refsGRPC.ContainerID))
		m.SetFilters(SearchFiltersToGRPC(r.filters))
		m.SetVersion(r.version)
	}

	return m
}

func (r *SearchRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.SearchRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	cid := v.GetContainerId()
	if cid == nil {
		r.cid = nil
	} else {
		if r.cid == nil {
			r.cid = new(refs.ContainerID)
		}

		err = r.cid.FromGRPCMessage(cid)
		if err != nil {
			return err
		}
	}

	r.filters, err = SearchFiltersFromGRPC(v.GetFilters())
	if err != nil {
		return err
	}

	r.version = v.GetVersion()

	return nil
}

func (r *SearchRequest) ToGRPCMessage() grpc.Message {
	var m *object.SearchRequest

	if r != nil {
		m = new(object.SearchRequest)

		m.SetBody(r.body.ToGRPCMessage().(*object.SearchRequest_Body))
		r.RequestHeaders.ToMessage(m)
	}

	return m
}

func (r *SearchRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.SearchRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(SearchRequestBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.RequestHeaders.FromMessage(v)
}

func (r *SearchResponseBody) ToGRPCMessage() grpc.Message {
	var m *object.SearchResponse_Body

	if r != nil {
		m = new(object.SearchResponse_Body)

		m.SetIdList(refs.ObjectIDListToGRPCMessage(r.idList))
	}

	return m
}

func (r *SearchResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.SearchResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	r.idList, err = refs.ObjectIDListFromGRPCMessage(v.GetIdList())

	return err
}

func (r *SearchResponse) ToGRPCMessage() grpc.Message {
	var m *object.SearchResponse

	if r != nil {
		m = new(object.SearchResponse)

		m.SetBody(r.body.ToGRPCMessage().(*object.SearchResponse_Body))
		r.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (r *SearchResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.SearchResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(SearchResponseBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.ResponseHeaders.FromMessage(v)
}

func (r *Range) ToGRPCMessage() grpc.Message {
	var m *object.Range

	if r != nil {
		m = new(object.Range)

		m.SetLength(r.len)
		m.SetOffset(r.off)
	}

	return m
}

func (r *Range) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.Range)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	r.len = v.GetLength()
	r.off = v.GetOffset()

	return nil
}

func RangesToGRPC(rs []Range) (res []*object.Range) {
	if rs != nil {
		res = make([]*object.Range, 0, len(rs))

		for i := range rs {
			res = append(res, rs[i].ToGRPCMessage().(*object.Range))
		}
	}

	return
}

func RangesFromGRPC(rs []*object.Range) (res []Range, err error) {
	if rs != nil {
		res = make([]Range, len(rs))

		for i := range rs {
			if rs[i] != nil {
				err = res[i].FromGRPCMessage(rs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (r *GetRangeRequestBody) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeRequest_Body

	if r != nil {
		m = new(object.GetRangeRequest_Body)

		m.SetAddress(r.addr.ToGRPCMessage().(*refsGRPC.Address))
		m.SetRange(r.rng.ToGRPCMessage().(*object.Range))
		m.SetRaw(r.raw)
	}

	return m
}

func (r *GetRangeRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	addr := v.GetAddress()
	if addr == nil {
		r.addr = nil
	} else {
		if r.addr == nil {
			r.addr = new(refs.Address)
		}

		err = r.addr.FromGRPCMessage(addr)
		if err != nil {
			return err
		}
	}

	rng := v.GetRange()
	if rng == nil {
		r.rng = nil
	} else {
		if r.rng == nil {
			r.rng = new(Range)
		}

		err = r.rng.FromGRPCMessage(rng)
		if err != nil {
			return err
		}
	}

	r.raw = v.GetRaw()

	return nil
}

func (r *GetRangeRequest) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeRequest

	if r != nil {
		m = new(object.GetRangeRequest)

		m.SetBody(r.body.ToGRPCMessage().(*object.GetRangeRequest_Body))
		r.RequestHeaders.ToMessage(m)
	}

	return m
}

func (r *GetRangeRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(GetRangeRequestBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.RequestHeaders.FromMessage(v)
}

func (r *GetRangePartChunk) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeResponse_Body_Chunk

	if r != nil {
		m = new(object.GetRangeResponse_Body_Chunk)

		m.SetChunk(r.chunk)
	}

	return m
}

func (r *GetRangePartChunk) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeResponse_Body_Chunk)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	r.chunk = v.GetChunk()

	return nil
}

func (r *GetRangeResponseBody) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeResponse_Body

	if r != nil {
		m = new(object.GetRangeResponse_Body)

		switch v := r.rngPart.(type) {
		case nil:
			m.RangePart = nil
		case *GetRangePartChunk:
			m.SetChunk(v.ToGRPCMessage().(*object.GetRangeResponse_Body_Chunk))
		case *SplitInfo:
			m.SetSplitInfo(v.ToGRPCMessage().(*object.SplitInfo))
		default:
			panic(fmt.Sprintf("unknown get range part %T", v))
		}
	}

	return m
}

func (r *GetRangeResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	r.rngPart = nil

	switch pt := v.GetRangePart().(type) {
	case nil:
	case *object.GetRangeResponse_Body_Chunk:
		if pt != nil {
			partChunk := new(GetRangePartChunk)
			r.rngPart = partChunk
			err = partChunk.FromGRPCMessage(pt)
		}
	case *object.GetRangeResponse_Body_SplitInfo:
		if pt != nil {
			partSplit := new(SplitInfo)
			r.rngPart = partSplit
			err = partSplit.FromGRPCMessage(pt.SplitInfo)
		}
	default:
		err = fmt.Errorf("unknown get range part %T", pt)
	}

	return err
}

func (r *GetRangeResponse) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeResponse

	if r != nil {
		m = new(object.GetRangeResponse)

		m.SetBody(r.body.ToGRPCMessage().(*object.GetRangeResponse_Body))
		r.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (r *GetRangeResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(GetRangeResponseBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.ResponseHeaders.FromMessage(v)
}

func (r *GetRangeHashRequestBody) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeHashRequest_Body

	if r != nil {
		m = new(object.GetRangeHashRequest_Body)

		m.SetAddress(r.addr.ToGRPCMessage().(*refsGRPC.Address))
		m.SetRanges(RangesToGRPC(r.rngs))
		m.SetType(refs.ChecksumTypeToGRPC(r.typ))
		m.SetSalt(r.salt)
	}

	return m
}

func (r *GetRangeHashRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeHashRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	addr := v.GetAddress()
	if addr == nil {
		r.addr = nil
	} else {
		if r.addr == nil {
			r.addr = new(refs.Address)
		}

		err = r.addr.FromGRPCMessage(addr)
		if err != nil {
			return err
		}
	}

	r.rngs, err = RangesFromGRPC(v.GetRanges())
	if err != nil {
		return err
	}

	r.typ = refs.ChecksumTypeFromGRPC(v.GetType())
	r.salt = v.GetSalt()

	return nil
}

func (r *GetRangeHashRequest) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeHashRequest

	if r != nil {
		m = new(object.GetRangeHashRequest)

		m.SetBody(r.body.ToGRPCMessage().(*object.GetRangeHashRequest_Body))
		r.RequestHeaders.ToMessage(m)
	}

	return m
}

func (r *GetRangeHashRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeHashRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(GetRangeHashRequestBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.RequestHeaders.FromMessage(v)
}

func (r *GetRangeHashResponseBody) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeHashResponse_Body

	if r != nil {
		m = new(object.GetRangeHashResponse_Body)

		m.SetType(refs.ChecksumTypeToGRPC(r.typ))
		m.SetHashList(r.hashList)
	}

	return m
}

func (r *GetRangeHashResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeHashResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	r.typ = refs.ChecksumTypeFromGRPC(v.GetType())
	r.hashList = v.GetHashList()

	return nil
}

func (r *GetRangeHashResponse) ToGRPCMessage() grpc.Message {
	var m *object.GetRangeHashResponse

	if r != nil {
		m = new(object.GetRangeHashResponse)

		m.SetBody(r.body.ToGRPCMessage().(*object.GetRangeHashResponse_Body))
		r.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (r *GetRangeHashResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*object.GetRangeHashResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		r.body = nil
	} else {
		if r.body == nil {
			r.body = new(GetRangeHashResponseBody)
		}

		err = r.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return r.ResponseHeaders.FromMessage(v)
}
