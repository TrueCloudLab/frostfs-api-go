package reputation

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
)

// PeerID represents reputation.PeerID message
// from NeoFS API v2.
type PeerID struct {
	publicKey []byte
}

// GetPublicKey returns peer's binary public key of ID.
func (x *PeerID) GetPublicKey() []byte {
	if x != nil {
		return x.publicKey
	}

	return nil
}

// SetPublicKey sets peer's binary public key of ID.
func (x *PeerID) SetPublicKey(v []byte) {
	x.publicKey = v
}

// Trust represents reputation.Trust message
// from NeoFS API v2.
type Trust struct {
	val float64

	peer *PeerID
}

// GetPeer returns trusted peer's ID.
func (x *Trust) GetPeer() *PeerID {
	if x != nil {
		return x.peer
	}

	return nil
}

// SetPeer sets trusted peer's ID.
func (x *Trust) SetPeer(v *PeerID) {
	x.peer = v
}

// GetValue returns trust value.
func (x *Trust) GetValue() float64 {
	if x != nil {
		return x.val
	}

	return 0
}

// SetValue sets trust value.
func (x *Trust) SetValue(v float64) {
	x.val = v
}

// PeerToPeerTrust represents reputation.PeerToPeerTrust message
// from NeoFS API v2.
type PeerToPeerTrust struct {
	trusting *PeerID

	trust *Trust
}

// GetTrustingPeer returns trusting peer ID.
func (x *PeerToPeerTrust) GetTrustingPeer() *PeerID {
	if x != nil {
		return x.trusting
	}

	return nil
}

// SetTrustingPeer sets trusting peer ID.
func (x *PeerToPeerTrust) SetTrustingPeer(v *PeerID) {
	x.trusting = v
}

// GetTrust returns trust value of trusting peer to the trusted one.
func (x *PeerToPeerTrust) GetTrust() *Trust {
	if x != nil {
		return x.trust
	}

	return nil
}

// SetTrust sets trust value of trusting peer to the trusted one.
func (x *PeerToPeerTrust) SetTrust(v *Trust) {
	x.trust = v
}

// GlobalTrustBody represents reputation.GlobalTrust.Body message
// from NeoFS API v2.
type GlobalTrustBody struct {
	manager *PeerID

	trust *Trust
}

// GetManager returns node manager ID.
func (x *GlobalTrustBody) GetManager() *PeerID {
	if x != nil {
		return x.manager
	}

	return nil
}

// SetManager sets node manager ID.
func (x *GlobalTrustBody) SetManager(v *PeerID) {
	x.manager = v
}

// GetTrust returns global trust value.
func (x *GlobalTrustBody) GetTrust() *Trust {
	if x != nil {
		return x.trust
	}

	return nil
}

// SetTrust sets global trust value.
func (x *GlobalTrustBody) SetTrust(v *Trust) {
	x.trust = v
}

// GlobalTrust represents reputation.GlobalTrust message
// from NeoFS API v2.
type GlobalTrust struct {
	version *refs.Version

	body *GlobalTrustBody

	sig *refs.Signature
}

// GetVersion returns message format version.
func (x *GlobalTrust) GetVersion() *refs.Version {
	if x != nil {
		return x.version
	}

	return nil
}

// SetVersion sets message format version.
func (x *GlobalTrust) SetVersion(v *refs.Version) {
	x.version = v
}

// GetBody returns message body.
func (x *GlobalTrust) GetBody() *GlobalTrustBody {
	if x != nil {
		return x.body
	}

	return nil
}

// SetBody sets message body.
func (x *GlobalTrust) SetBody(v *GlobalTrustBody) {
	x.body = v
}

// GetSignature returns body signature.
func (x *GlobalTrust) GetSignature() *refs.Signature {
	if x != nil {
		return x.sig
	}

	return nil
}

// SetSignature sets body signature.
func (x *GlobalTrust) SetSignature(v *refs.Signature) {
	x.sig = v
}

// AnnounceLocalTrustRequestBody is a structure of AnnounceLocalTrust request body.
type AnnounceLocalTrustRequestBody struct {
	epoch uint64

	trusts []Trust
}

// GetEpoch returns epoch in which the trust was assessed.
func (x *AnnounceLocalTrustRequestBody) GetEpoch() uint64 {
	if x != nil {
		return x.epoch
	}

	return 0
}

// SetEpoch sets epoch in which the trust was assessed.
func (x *AnnounceLocalTrustRequestBody) SetEpoch(v uint64) {
	x.epoch = v
}

// GetTrusts returns list of normalized trust values.
func (x *AnnounceLocalTrustRequestBody) GetTrusts() []Trust {
	if x != nil {
		return x.trusts
	}

	return nil
}

// SetTrusts sets list of normalized trust values.
func (x *AnnounceLocalTrustRequestBody) SetTrusts(v []Trust) {
	x.trusts = v
}

// AnnounceLocalTrustResponseBody is a structure of AnnounceLocalTrust response body.
type AnnounceLocalTrustResponseBody struct{}

// AnnounceLocalTrustRequest represents reputation.AnnounceLocalTrustRequest
// message from NeoFS API v2.
type AnnounceLocalTrustRequest struct {
	body *AnnounceLocalTrustRequestBody

	session.RequestHeaders
}

// GetBody returns request body.
func (x *AnnounceLocalTrustRequest) GetBody() *AnnounceLocalTrustRequestBody {
	if x != nil {
		return x.body
	}

	return nil
}

// SetBody sets request body.
func (x *AnnounceLocalTrustRequest) SetBody(v *AnnounceLocalTrustRequestBody) {
	x.body = v
}

// AnnounceLocalTrustResponse represents reputation.AnnounceLocalTrustResponse
// message from NeoFS API v2.
type AnnounceLocalTrustResponse struct {
	body *AnnounceLocalTrustResponseBody

	session.ResponseHeaders
}

// GetBody returns response body.
func (x *AnnounceLocalTrustResponse) GetBody() *AnnounceLocalTrustResponseBody {
	if x != nil {
		return x.body
	}

	return nil
}

// SetBody sets response body.
func (x *AnnounceLocalTrustResponse) SetBody(v *AnnounceLocalTrustResponseBody) {
	x.body = v
}

// AnnounceIntermediateResultRequestBody is a structure of AnnounceIntermediateResult request body.
type AnnounceIntermediateResultRequestBody struct {
	epoch uint64

	iter uint32

	trust *PeerToPeerTrust
}

// GetEpoch returns epoch number in which the intermediate trust was assessed.
func (x *AnnounceIntermediateResultRequestBody) GetEpoch() uint64 {
	if x != nil {
		return x.epoch
	}

	return 0
}

// SetEpoch sets epoch number in which the intermediate trust was assessed.
func (x *AnnounceIntermediateResultRequestBody) SetEpoch(v uint64) {
	x.epoch = v
}

// GetIteration returns sequence number of the iteration.
func (x *AnnounceIntermediateResultRequestBody) GetIteration() uint32 {
	if x != nil {
		return x.iter
	}

	return 0
}

// SetIteration sets sequence number of the iteration.
func (x *AnnounceIntermediateResultRequestBody) SetIteration(v uint32) {
	x.iter = v
}

// GetTrust returns current global trust value.
func (x *AnnounceIntermediateResultRequestBody) GetTrust() *PeerToPeerTrust {
	if x != nil {
		return x.trust
	}

	return nil
}

// SetTrust sets current global trust value.
func (x *AnnounceIntermediateResultRequestBody) SetTrust(v *PeerToPeerTrust) {
	x.trust = v
}

// AnnounceIntermediateResultResponseBody is a structure of AnnounceIntermediateResult response body.
type AnnounceIntermediateResultResponseBody struct{}

// AnnounceIntermediateResultRequest represents reputation.AnnounceIntermediateResult
// message from NeoFS API v2.
type AnnounceIntermediateResultRequest struct {
	body *AnnounceIntermediateResultRequestBody

	session.RequestHeaders
}

// GetBody returns request body.
func (x *AnnounceIntermediateResultRequest) GetBody() *AnnounceIntermediateResultRequestBody {
	if x != nil {
		return x.body
	}

	return nil
}

// SetBody sets request body.
func (x *AnnounceIntermediateResultRequest) SetBody(v *AnnounceIntermediateResultRequestBody) {
	x.body = v
}

// AnnounceIntermediateResultResponse represents reputation.AnnounceIntermediateResultResponse
// message from NeoFS API v2.
type AnnounceIntermediateResultResponse struct {
	body *AnnounceIntermediateResultResponseBody

	session.ResponseHeaders
}

// GetBody returns response body.
func (x *AnnounceIntermediateResultResponse) GetBody() *AnnounceIntermediateResultResponseBody {
	if x != nil {
		return x.body
	}

	return nil
}

// SetBody sets response body.
func (x *AnnounceIntermediateResultResponse) SetBody(v *AnnounceIntermediateResultResponseBody) {
	x.body = v
}
