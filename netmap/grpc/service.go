package netmap

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// SetBody sets body of the request.
func (m *LocalNodeInfoRequest) SetBody(v *LocalNodeInfoRequest_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the request.
func (m *LocalNodeInfoRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (m *LocalNodeInfoRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	m.VerifyHeader = v
}

// SetVersion sets version of response body.
func (m *LocalNodeInfoResponse_Body) SetVersion(v *refs.Version) {
	m.Version = v
}

// SetNodeInfo sets node info of response body.
func (m *LocalNodeInfoResponse_Body) SetNodeInfo(v *NodeInfo) {
	m.NodeInfo = v
}

// SetBody sets body of the response.
func (m *LocalNodeInfoResponse) SetBody(v *LocalNodeInfoResponse_Body) {
	m.Body = v
}

// SetMetaHeader sets meta header of the response.
func (m *LocalNodeInfoResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	m.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (m *LocalNodeInfoResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	m.VerifyHeader = v
}

// SetBody sets body of the request.
func (x *NetworkInfoRequest) SetBody(v *NetworkInfoRequest_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the request.
func (x *NetworkInfoRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (x *NetworkInfoRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	x.VerifyHeader = v
}

// SetNetworkInfo sets information about the network.
func (x *NetworkInfoResponse_Body) SetNetworkInfo(v *NetworkInfo) {
	x.NetworkInfo = v
}

// SetBody sets body of the response.
func (x *NetworkInfoResponse) SetBody(v *NetworkInfoResponse_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the response.
func (x *NetworkInfoResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (x *NetworkInfoResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	x.VerifyHeader = v
}

// SetBody sets body of the request.
func (x *NetmapSnapshotRequest) SetBody(v *NetmapSnapshotRequest_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the request.
func (x *NetmapSnapshotRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (x *NetmapSnapshotRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	x.VerifyHeader = v
}

// SetNetmap sets current Netmap.
func (x *NetmapSnapshotResponse_Body) SetNetmap(v *Netmap) {
	x.Netmap = v
}

// SetBody sets body of the response.
func (x *NetmapSnapshotResponse) SetBody(v *NetmapSnapshotResponse_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the response.
func (x *NetmapSnapshotResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (x *NetmapSnapshotResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	x.VerifyHeader = v
}
