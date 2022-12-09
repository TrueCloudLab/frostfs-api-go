package container

import (
	acl "github.com/TrueCloudLab/frostfs-api-go/v2/acl/grpc"
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// SetContainer sets container of the request.
func (m *PutRequest_Body) SetContainer(v *Container) {
	m.Container = v
}

// SetSignature sets signature of the container structure.
func (m *PutRequest_Body) SetSignature(v *refs.SignatureRFC6979) {
	m.Signature = v
}

// SetBody sets body of the request.
func (m *PutRequest) SetBody(v *PutRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *PutRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *PutRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetContainerId sets identifier of the container.
func (m *PutResponse_Body) SetContainerId(v *refs.ContainerID) {
	m.ContainerId = v
}

// SetBody sets body of the response.
func (m *PutResponse) SetBody(v *PutResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *PutResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *PutResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetContainerId sets identifier of the container.
func (m *DeleteRequest_Body) SetContainerId(v *refs.ContainerID) {
	m.ContainerId = v
}

// SetSignature sets signature of the container identifier.
func (m *DeleteRequest_Body) SetSignature(v *refs.SignatureRFC6979) {
	m.Signature = v
}

// SetBody sets body of the request.
func (m *DeleteRequest) SetBody(v *DeleteRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *DeleteRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *DeleteRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetBody sets body of the response.
func (m *DeleteResponse) SetBody(v *DeleteResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *DeleteResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *DeleteResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetContainerId sets identifier of the container.
func (m *GetRequest_Body) SetContainerId(v *refs.ContainerID) {
	m.ContainerId = v
}

// SetBody sets body of the request.
func (m *GetRequest) SetBody(v *GetRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *GetRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *GetRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetContainer sets the container structure.
func (m *GetResponse_Body) SetContainer(v *Container) {
	m.Container = v
}

// SetSessionToken sets token of the session within which requested
// container was created.
func (m *GetResponse_Body) SetSessionToken(v *session.SessionToken) {
	m.SessionToken = v
}

// SetSignature sets signature of the container structure.
func (m *GetResponse_Body) SetSignature(v *refs.SignatureRFC6979) {
	m.Signature = v
}

// SetBody sets body of the response.
func (m *GetResponse) SetBody(v *GetResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *GetResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *GetResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetOwnerId sets identifier of the container owner.
func (m *ListRequest_Body) SetOwnerId(v *refs.OwnerID) {
	m.OwnerId = v
}

// SetBody sets body of the request.
func (m *ListRequest) SetBody(v *ListRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *ListRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *ListRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetContainerIds sets list of the container identifiers.
func (m *ListResponse_Body) SetContainerIds(v []*refs.ContainerID) {
	m.ContainerIds = v
}

// SetBody sets body of the response.
func (m *ListResponse) SetBody(v *ListResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *ListResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *ListResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetEacl sets eACL table structure.
func (m *SetExtendedACLRequest_Body) SetEacl(v *acl.EACLTable) {
	m.Eacl = v
}

// SetSignature sets signature of the eACL table structure.
func (m *SetExtendedACLRequest_Body) SetSignature(v *refs.SignatureRFC6979) {
	m.Signature = v
}

// SetBody sets body of the request.
func (m *SetExtendedACLRequest) SetBody(v *SetExtendedACLRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *SetExtendedACLRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *SetExtendedACLRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetBody sets body of the response.
func (m *SetExtendedACLResponse) SetBody(v *SetExtendedACLResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *SetExtendedACLResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *SetExtendedACLResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetContainerId sets identifier of the container.
func (m *GetExtendedACLRequest_Body) SetContainerId(v *refs.ContainerID) {
	m.ContainerId = v
}

// SetBody sets body of the request.
func (m *GetExtendedACLRequest) SetBody(v *GetExtendedACLRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *GetExtendedACLRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *GetExtendedACLRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetEacl sets eACL table structure.
func (m *GetExtendedACLResponse_Body) SetEacl(v *acl.EACLTable) {
	m.Eacl = v
}

// SetSignature sets signature of the eACL table structure.
func (m *GetExtendedACLResponse_Body) SetSignature(v *refs.SignatureRFC6979) {
	m.Signature = v
}

// SetSessionToken sets token of the session within which requested
// eACl table was set.
func (m *GetExtendedACLResponse_Body) SetSessionToken(v *session.SessionToken) {
	m.SessionToken = v
}

// SetBody sets body of the response.
func (m *GetExtendedACLResponse) SetBody(v *GetExtendedACLResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *GetExtendedACLResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *GetExtendedACLResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetEpoch sets epoch of the size estimation.
func (m *AnnounceUsedSpaceRequest_Body_Announcement) SetEpoch(v uint64) {
	m.Epoch = v
}

// SetContainerId sets identifier of the container.
func (m *AnnounceUsedSpaceRequest_Body_Announcement) SetContainerId(v *refs.ContainerID) {
	m.ContainerId = v
}

// SetUsedSpace sets used space value of the container.
func (m *AnnounceUsedSpaceRequest_Body_Announcement) SetUsedSpace(v uint64) {
	m.UsedSpace = v
}

// SetAnnouncements sets list of announcement for shared containers between nodes.
func (m *AnnounceUsedSpaceRequest_Body) SetAnnouncements(v []*AnnounceUsedSpaceRequest_Body_Announcement) {
	m.Announcements = v
}

// SetBody sets body of the request.
func (m *AnnounceUsedSpaceRequest) SetBody(v *AnnounceUsedSpaceRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *AnnounceUsedSpaceRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *AnnounceUsedSpaceRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetBody sets body of the response.
func (m *AnnounceUsedSpaceResponse) SetBody(v *AnnounceUsedSpaceResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *AnnounceUsedSpaceResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *AnnounceUsedSpaceResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}
