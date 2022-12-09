package reputation

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// SetPublicKey sets binary public key of ID.
func (x *PeerID) SetPublicKey(v []byte) {
	x.PublicKey = v
}

// SetPeer sets trusted peer's ID.
func (x *Trust) SetPeer(v *PeerID) {
	x.Peer = v
}

// SetValue sets trust value.
func (x *Trust) SetValue(v float64) {
	x.Value = v
}

// SetTrustingPeer sets trusting peer ID.
func (x *PeerToPeerTrust) SetTrustingPeer(v *PeerID) {
	x.TrustingPeer = v
}

// SetTrust sets trust value of trusting peer to the trusted one.
func (x *PeerToPeerTrust) SetTrust(v *Trust) {
	x.Trust = v
}

// SetManager sets manager ID.
func (x *GlobalTrust_Body) SetManager(v *PeerID) {
	x.Manager = v
}

// SetTrust sets global trust value.
func (x *GlobalTrust_Body) SetTrust(v *Trust) {
	x.Trust = v
}

// SetVersion sets message format version.
func (x *GlobalTrust) SetVersion(v *refs.Version) {
	x.Version = v
}

// SetBody sets message body.
func (x *GlobalTrust) SetBody(v *GlobalTrust_Body) {
	x.Body = v
}

// SetSignature sets body signature.
func (x *GlobalTrust) SetSignature(v *refs.Signature) {
	x.Signature = v
}
