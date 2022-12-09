package reputation

import (
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
)

// SetEpoch sets epoch in which the trust was assessed.
func (x *AnnounceLocalTrustRequest_Body) SetEpoch(v uint64) {
	x.Epoch = v
}

// SetTrusts sets list of normalized trust values.
func (x *AnnounceLocalTrustRequest_Body) SetTrusts(v []*Trust) {
	x.Trusts = v
}

// SetBody sets body of the request.
func (x *AnnounceLocalTrustRequest) SetBody(v *AnnounceLocalTrustRequest_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the request.
func (x *AnnounceLocalTrustRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (x *AnnounceLocalTrustRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	x.VerifyHeader = v
}

// SetBody sets body of the response.
func (x *AnnounceLocalTrustResponse) SetBody(v *AnnounceLocalTrustResponse_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the response.
func (x *AnnounceLocalTrustResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (x *AnnounceLocalTrustResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	x.VerifyHeader = v
}

// SetEpoch sets epoch in which the intermediate trust was assessed.
func (x *AnnounceIntermediateResultRequest_Body) SetEpoch(v uint64) {
	x.Epoch = v
}

// SetIteration sets sequence number of the iteration.
func (x *AnnounceIntermediateResultRequest_Body) SetIteration(v uint32) {
	x.Iteration = v
}

// SetTrust sets current global trust value.
func (x *AnnounceIntermediateResultRequest_Body) SetTrust(v *PeerToPeerTrust) {
	x.Trust = v
}

// SetBody sets body of the request.
func (x *AnnounceIntermediateResultRequest) SetBody(v *AnnounceIntermediateResultRequest_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the request.
func (x *AnnounceIntermediateResultRequest) SetMetaHeader(v *session.RequestMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the request.
func (x *AnnounceIntermediateResultRequest) SetVerifyHeader(v *session.RequestVerificationHeader) {
	x.VerifyHeader = v
}

// SetBody sets body of the response.
func (x *AnnounceIntermediateResultResponse) SetBody(v *AnnounceIntermediateResultResponse_Body) {
	x.Body = v
}

// SetMetaHeader sets meta header of the response.
func (x *AnnounceIntermediateResultResponse) SetMetaHeader(v *session.ResponseMetaHeader) {
	x.MetaHeader = v
}

// SetVerifyHeader sets verification header of the response.
func (x *AnnounceIntermediateResultResponse) SetVerifyHeader(v *session.ResponseVerificationHeader) {
	x.VerifyHeader = v
}
