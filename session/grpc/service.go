package session

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// SetOwnerId sets identifier of the session initiator.
func (m *CreateRequest_Body) SetOwnerId(v *refs.OwnerID) {
	m.OwnerId = v
}

// SetExpiration sets lifetime of the session.
func (m *CreateRequest_Body) SetExpiration(v uint64) {
	m.Expiration = v
}

// SetBody sets body of the request.
func (m *CreateRequest) SetBody(v *CreateRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *CreateRequest) SetMetaHeader(v *RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *CreateRequest) SetVerifyHeader(v *RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetId sets identifier of the session token.
func (m *CreateResponse_Body) SetId(v []byte) {
	m.Id = v
}

// SetSessionKey sets session public key in a binary format.
func (m *CreateResponse_Body) SetSessionKey(v []byte) {
	m.SessionKey = v
}

// SetBody sets body of the response.
func (m *CreateResponse) SetBody(v *CreateResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *CreateResponse) SetMetaHeader(v *ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *CreateResponse) SetVerifyHeader(v *ResponseVerificationHeader) {
	m.VerifyHeader = v
}
