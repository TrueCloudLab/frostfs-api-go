package session

import (
	acl "github.com/TrueCloudLab/frostfs-api-go/v2/acl/grpc"
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	status "github.com/TrueCloudLab/frostfs-api-go/v2/status/grpc"
)

// SetKey sets key to the X-Header.
func (m *XHeader) SetKey(v string) {
	m.Key = v
}

// SetValue sets value of the X-Header.
func (m *XHeader) SetValue(v string) {
	m.Value = v
}

// SetExp sets epoch number of the token expiration.
func (m *SessionToken_Body_TokenLifetime) SetExp(v uint64) {
	m.Exp = v
}

// SetNbf sets starting epoch number of the token.
func (m *SessionToken_Body_TokenLifetime) SetNbf(v uint64) {
	m.Nbf = v
}

// SetIat sets the number of the epoch in which the token was issued.
func (m *SessionToken_Body_TokenLifetime) SetIat(v uint64) {
	m.Iat = v
}

// SetId sets identifier of the session token.
func (m *SessionToken_Body) SetId(v []byte) {
	m.Id = v
}

// SetOwnerId sets identifier of the session token owner.
func (m *SessionToken_Body) SetOwnerId(v *refs.OwnerID) {
	m.OwnerId = v
}

// SetLifetime sets lifetime of the session token.
func (m *SessionToken_Body) SetLifetime(v *SessionToken_Body_TokenLifetime) {
	m.Lifetime = v
}

// SetSessionKey sets public session key in a binary format.
func (m *SessionToken_Body) SetSessionKey(v []byte) {
	m.SessionKey = v
}

// SetObjectAddressContext sets object context of the session token.
func (m *SessionToken_Body) SetObjectSessionContext(v *ObjectSessionContext) {
	m.Context = &SessionToken_Body_Object{
		Object: v,
	}
}

// SetContainerSessionContext sets container context of the session token.
func (m *SessionToken_Body) SetContainerSessionContext(v *ContainerSessionContext) {
	m.Context = &SessionToken_Body_Container{
		Container: v,
	}
}

// SetTarget specifies objects involved in the object session.
func (m *ObjectSessionContext) SetTarget(cnr *refs.ContainerID, objs []*refs.ObjectID) {
	m.Target = &ObjectSessionContext_Target{
		Container: cnr,
		Objects:   objs,
	}
}

// SetVerb sets type of request for which the token is issued.
func (m *ObjectSessionContext) SetVerb(v ObjectSessionContext_Verb) {
	m.Verb = v
}

// SetVerb sets type of request for which the token is issued.
func (x *ContainerSessionContext) SetVerb(v ContainerSessionContext_Verb) {
	x.Verb = v
}

// SetWildcard sets wildcard flag of the container session.
func (x *ContainerSessionContext) SetWildcard(v bool) {
	x.Wildcard = v
}

// SetContainerId sets identifier of the container related to the session.
func (x *ContainerSessionContext) SetContainerId(v *refs.ContainerID) {
	x.ContainerId = v
}

// SetBody sets session token body.
func (m *SessionToken) SetBody(v *SessionToken_Body) {
	m.Body = v
}

// SetSignature sets session token signature.
func (m *SessionToken) SetSignature(v *refs.Signature) {
	m.Signature = v
}

// SetVersion sets client protocol version.
func (m *RequestMetaHeader) SetVersion(v *refs.Version) {
	m.Version = v
}

// SetEpoch sets client local epoch.
func (m *RequestMetaHeader) SetEpoch(v uint64) {
	m.Epoch = v
}

// SetTtl sets request TTL.
func (m *RequestMetaHeader) SetTtl(v uint32) {
	m.Ttl = v
}

// SetXHeaders sets request X-Headers.
func (m *RequestMetaHeader) SetXHeaders(v []*XHeader) {
	m.XHeaders = v
}

// SetSessionToken sets session token of the request.
func (m *RequestMetaHeader) SetSessionToken(v *SessionToken) {
	m.SessionToken = v
}

// SetBearerToken sets bearer token of the request.
func (m *RequestMetaHeader) SetBearerToken(v *acl.BearerToken) {
	m.BearerToken = v
}

// SetOrigin sets origin request meta header.
func (m *RequestMetaHeader) SetOrigin(v *RequestMetaHeader) {
	m.Origin = v
}

// GetNetworkMagic returns NeoFS network magic.
func (m *RequestMetaHeader) GetNetworkMagic() uint64 {
	if m != nil {
		return m.MagicNumber
	}

	return 0
}

// SetNetworkMagic sets NeoFS network magic.
func (m *RequestMetaHeader) SetNetworkMagic(v uint64) {
	m.MagicNumber = v
}

// SetVersion sets server protocol version.
func (m *ResponseMetaHeader) SetVersion(v *refs.Version) {
	m.Version = v
}

// SetEpoch sets server local epoch.
func (m *ResponseMetaHeader) SetEpoch(v uint64) {
	m.Epoch = v
}

// SetTtl sets response TTL.
func (m *ResponseMetaHeader) SetTtl(v uint32) {
	m.Ttl = v
}

// SetXHeaders sets response X-Headers.
func (m *ResponseMetaHeader) SetXHeaders(v []*XHeader) {
	m.XHeaders = v
}

// SetOrigin sets origin response meta header.
func (m *ResponseMetaHeader) SetOrigin(v *ResponseMetaHeader) {
	m.Origin = v
}

// SetStatus sets response status.
func (m *ResponseMetaHeader) SetStatus(v *status.Status) {
	m.Status = v
}

// SetBodySignature sets signature of the request body.
func (m *RequestVerificationHeader) SetBodySignature(v *refs.Signature) {
	m.BodySignature = v
}

// SetMetaSignature sets signature of the request meta.
func (m *RequestVerificationHeader) SetMetaSignature(v *refs.Signature) {
	m.MetaSignature = v
}

// SetOriginSignature sets signature of the origin verification header of the request.
func (m *RequestVerificationHeader) SetOriginSignature(v *refs.Signature) {
	m.OriginSignature = v
}

// SetOrigin sets origin verification header of the request.
func (m *RequestVerificationHeader) SetOrigin(v *RequestVerificationHeader) {
	m.Origin = v
}

// SetBodySignature sets signature of the response body.
func (m *ResponseVerificationHeader) SetBodySignature(v *refs.Signature) {
	m.BodySignature = v
}

// SetMetaSignature sets signature of the response meta.
func (m *ResponseVerificationHeader) SetMetaSignature(v *refs.Signature) {
	m.MetaSignature = v
}

// SetOriginSignature sets signature of the origin verification header of the response.
func (m *ResponseVerificationHeader) SetOriginSignature(v *refs.Signature) {
	m.OriginSignature = v
}

// SetOrigin sets origin verification header of the response.
func (m *ResponseVerificationHeader) SetOrigin(v *ResponseVerificationHeader) {
	m.Origin = v
}

// FromString parses ObjectSessionContext_Verb from a string representation,
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *ObjectSessionContext_Verb) FromString(s string) bool {
	i, ok := ObjectSessionContext_Verb_value[s]
	if ok {
		*x = ObjectSessionContext_Verb(i)
	}

	return ok
}

// FromString parses ContainerSessionContext_Verb from a string representation,
// It is a reverse action to String().
//
// Returns true if s was parsed successfully.
func (x *ContainerSessionContext_Verb) FromString(s string) bool {
	i, ok := ContainerSessionContext_Verb_value[s]
	if ok {
		*x = ContainerSessionContext_Verb(i)
	}

	return ok
}
