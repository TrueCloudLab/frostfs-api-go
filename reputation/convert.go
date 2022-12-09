package reputation

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	reputation "github.com/TrueCloudLab/frostfs-api-go/v2/reputation/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

// ToGRPCMessage converts PeerID to gRPC-generated
// reputation.PeerID message.
func (x *PeerID) ToGRPCMessage() grpc.Message {
	var m *reputation.PeerID

	if x != nil {
		m = new(reputation.PeerID)

		m.SetPublicKey(x.publicKey)
	}

	return m
}

// FromGRPCMessage tries to restore PeerID from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.PeerID message.
func (x *PeerID) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.PeerID)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	x.publicKey = v.GetPublicKey()

	return nil
}

// ToGRPCMessage converts Trust to gRPC-generated
// reputation.Trust message.
func (x *Trust) ToGRPCMessage() grpc.Message {
	var m *reputation.Trust

	if x != nil {
		m = new(reputation.Trust)

		m.SetValue(x.val)
		m.SetPeer(x.peer.ToGRPCMessage().(*reputation.PeerID))
	}

	return m
}

// FromGRPCMessage tries to restore Trust from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.Trust message.
func (x *Trust) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.Trust)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	peer := v.GetPeer()
	if peer == nil {
		x.peer = nil
	} else {
		if x.peer == nil {
			x.peer = new(PeerID)
		}

		err := x.peer.FromGRPCMessage(peer)
		if err != nil {
			return err
		}
	}

	x.val = v.GetValue()

	return nil
}

// ToGRPCMessage converts PeerToPeerTrust to gRPC-generated
// reputation.PeerToPeerTrust message.
func (x *PeerToPeerTrust) ToGRPCMessage() grpc.Message {
	var m *reputation.PeerToPeerTrust

	if x != nil {
		m = new(reputation.PeerToPeerTrust)

		m.SetTrustingPeer(x.trusting.ToGRPCMessage().(*reputation.PeerID))
		m.SetTrust(x.trust.ToGRPCMessage().(*reputation.Trust))
	}

	return m
}

// FromGRPCMessage tries to restore PeerToPeerTrust from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.PeerToPeerTrust message.
func (x *PeerToPeerTrust) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.PeerToPeerTrust)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	trusting := v.GetTrustingPeer()
	if trusting == nil {
		x.trusting = nil
	} else {
		if x.trusting == nil {
			x.trusting = new(PeerID)
		}

		err = x.trusting.FromGRPCMessage(trusting)
		if err != nil {
			return err
		}
	}

	trust := v.GetTrust()
	if trust == nil {
		x.trust = nil
	} else {
		if x.trust == nil {
			x.trust = new(Trust)
		}

		err = x.trust.FromGRPCMessage(trust)
	}

	return err
}

// TrustsToGRPC converts slice of Trust structures
// to slice of gRPC-generated Trust messages.
func TrustsToGRPC(xs []Trust) (res []*reputation.Trust) {
	if xs != nil {
		res = make([]*reputation.Trust, 0, len(xs))

		for i := range xs {
			res = append(res, xs[i].ToGRPCMessage().(*reputation.Trust))
		}
	}

	return
}

// TrustsFromGRPC tries to restore slice of Trust structures from
// slice of gRPC-generated reputation.Trust messages.
func TrustsFromGRPC(xs []*reputation.Trust) (res []Trust, err error) {
	if xs != nil {
		res = make([]Trust, len(xs))

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

// ToGRPCMessage converts GlobalTrustBody to gRPC-generated
// reputation.GlobalTrust_Body message.
func (x *GlobalTrustBody) ToGRPCMessage() grpc.Message {
	var m *reputation.GlobalTrust_Body

	if x != nil {
		m = new(reputation.GlobalTrust_Body)

		m.SetManager(x.manager.ToGRPCMessage().(*reputation.PeerID))
		m.SetTrust(x.trust.ToGRPCMessage().(*reputation.Trust))
	}

	return m
}

// FromGRPCMessage tries to restore GlobalTrustBody from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.GlobalTrust_Body message.
func (x *GlobalTrustBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.GlobalTrust_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	manager := v.GetManager()
	if manager == nil {
		x.manager = nil
	} else {
		if x.manager == nil {
			x.manager = new(PeerID)
		}

		err = x.manager.FromGRPCMessage(manager)
		if err != nil {
			return err
		}
	}

	trust := v.GetTrust()
	if trust == nil {
		x.trust = nil
	} else {
		if x.trust == nil {
			x.trust = new(Trust)
		}

		err = x.trust.FromGRPCMessage(trust)
	}

	return err
}

// ToGRPCMessage converts GlobalTrust to gRPC-generated
// reputation.GlobalTrust message.
func (x *GlobalTrust) ToGRPCMessage() grpc.Message {
	var m *reputation.GlobalTrust

	if x != nil {
		m = new(reputation.GlobalTrust)

		m.SetVersion(x.version.ToGRPCMessage().(*refsGRPC.Version))
		m.SetBody(x.body.ToGRPCMessage().(*reputation.GlobalTrust_Body))
		m.SetSignature(x.sig.ToGRPCMessage().(*refsGRPC.Signature))
	}

	return m
}

// FromGRPCMessage tries to restore GlobalTrust from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.GlobalTrust message.
func (x *GlobalTrust) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.GlobalTrust)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	version := v.GetVersion()
	if version == nil {
		x.version = nil
	} else {
		if x.version == nil {
			x.version = new(refs.Version)
		}

		err = x.version.FromGRPCMessage(version)
		if err != nil {
			return err
		}
	}

	body := v.GetBody()
	if body == nil {
		x.body = nil
	} else {
		if x.body == nil {
			x.body = new(GlobalTrustBody)
		}

		err = x.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	sig := v.GetSignature()
	if sig == nil {
		x.sig = nil
	} else {
		if x.sig == nil {
			x.sig = new(refs.Signature)
		}

		err = x.sig.FromGRPCMessage(sig)
	}

	return err
}

// ToGRPCMessage converts AnnounceLocalTrustRequestBody to gRPC-generated
// reputation.AnnounceLocalTrustRequest_Body message.
func (x *AnnounceLocalTrustRequestBody) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceLocalTrustRequest_Body

	if x != nil {
		m = new(reputation.AnnounceLocalTrustRequest_Body)

		m.SetEpoch(x.epoch)
		m.SetTrusts(TrustsToGRPC(x.trusts))
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceLocalTrustRequestBody from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceLocalTrustRequest_Body message.
func (x *AnnounceLocalTrustRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceLocalTrustRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	x.trusts, err = TrustsFromGRPC(v.GetTrusts())
	if err != nil {
		return err
	}

	x.epoch = v.GetEpoch()

	return nil
}

// ToGRPCMessage converts AnnounceLocalTrustRequest to gRPC-generated
// reputation.AnnounceLocalTrustRequest message.
func (x *AnnounceLocalTrustRequest) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceLocalTrustRequest

	if x != nil {
		m = new(reputation.AnnounceLocalTrustRequest)

		m.SetBody(x.body.ToGRPCMessage().(*reputation.AnnounceLocalTrustRequest_Body))
		x.RequestHeaders.ToMessage(m)
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceLocalTrustRequest from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceLocalTrustRequest message.
func (x *AnnounceLocalTrustRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceLocalTrustRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		x.body = nil
	} else {
		if x.body == nil {
			x.body = new(AnnounceLocalTrustRequestBody)
		}

		err = x.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return x.RequestHeaders.FromMessage(v)
}

// ToGRPCMessage converts AnnounceLocalTrustResponseBody to gRPC-generated
// reputation.AnnounceLocalTrustResponse_Body message.
func (x *AnnounceLocalTrustResponseBody) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceLocalTrustResponse_Body

	if x != nil {
		m = new(reputation.AnnounceLocalTrustResponse_Body)
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceLocalTrustResponseBody from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceLocalTrustResponse_Body message.
func (x *AnnounceLocalTrustResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceLocalTrustResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	return nil
}

// ToGRPCMessage converts AnnounceLocalTrustResponse to gRPC-generated
// reputation.AnnounceLocalTrustResponse message.
func (x *AnnounceLocalTrustResponse) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceLocalTrustResponse

	if x != nil {
		m = new(reputation.AnnounceLocalTrustResponse)

		m.SetBody(x.body.ToGRPCMessage().(*reputation.AnnounceLocalTrustResponse_Body))
		x.ResponseHeaders.ToMessage(m)
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceLocalTrustResponse from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceLocalTrustResponse message.
func (x *AnnounceLocalTrustResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceLocalTrustResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		x.body = nil
	} else {
		if x.body == nil {
			x.body = new(AnnounceLocalTrustResponseBody)
		}

		err = x.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return x.ResponseHeaders.FromMessage(v)
}

// ToGRPCMessage converts AnnounceIntermediateResultRequestBody to gRPC-generated
// reputation.AnnounceIntermediateResultRequest_Body message.
func (x *AnnounceIntermediateResultRequestBody) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceIntermediateResultRequest_Body

	if x != nil {
		m = new(reputation.AnnounceIntermediateResultRequest_Body)

		m.SetEpoch(x.epoch)
		m.SetIteration(x.iter)
		m.SetTrust(x.trust.ToGRPCMessage().(*reputation.PeerToPeerTrust))
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceIntermediateResultRequestBody from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceIntermediateResultRequest_Body message.
func (x *AnnounceIntermediateResultRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceIntermediateResultRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	trust := v.GetTrust()
	if trust == nil {
		x.trust = nil
	} else {
		if x.trust == nil {
			x.trust = new(PeerToPeerTrust)
		}

		err := x.trust.FromGRPCMessage(trust)
		if err != nil {
			return err
		}
	}

	x.epoch = v.GetEpoch()
	x.iter = v.GetIteration()

	return nil
}

// ToGRPCMessage converts AnnounceIntermediateResultRequest to gRPC-generated
// reputation.AnnounceIntermediateResultRequest message.
func (x *AnnounceIntermediateResultRequest) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceIntermediateResultRequest

	if x != nil {
		m = new(reputation.AnnounceIntermediateResultRequest)

		m.SetBody(x.body.ToGRPCMessage().(*reputation.AnnounceIntermediateResultRequest_Body))
		x.RequestHeaders.ToMessage(m)
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceIntermediateResultRequest from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceIntermediateResultRequest message.
func (x *AnnounceIntermediateResultRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceIntermediateResultRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		x.body = nil
	} else {
		if x.body == nil {
			x.body = new(AnnounceIntermediateResultRequestBody)
		}

		err = x.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return x.RequestHeaders.FromMessage(v)
}

// ToGRPCMessage converts AnnounceIntermediateResultResponseBody to gRPC-generated
// reputation.AnnounceIntermediateResultResponse_Body message.
func (x *AnnounceIntermediateResultResponseBody) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceIntermediateResultResponse_Body

	if x != nil {
		m = new(reputation.AnnounceIntermediateResultResponse_Body)
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceIntermediateResultResponseBody from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceIntermediateResultResponse_Body message.
func (x *AnnounceIntermediateResultResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceIntermediateResultResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	return nil
}

// ToGRPCMessage converts AnnounceIntermediateResultResponse to gRPC-generated
// reputation.AnnounceIntermediateResultResponse message.
func (x *AnnounceIntermediateResultResponse) ToGRPCMessage() grpc.Message {
	var m *reputation.AnnounceIntermediateResultResponse

	if x != nil {
		m = new(reputation.AnnounceIntermediateResultResponse)

		m.SetBody(x.body.ToGRPCMessage().(*reputation.AnnounceIntermediateResultResponse_Body))
		x.ResponseHeaders.ToMessage(m)
	}

	return m
}

// FromGRPCMessage tries to restore AnnounceIntermediateResultResponse from grpc.Message.
//
// Returns message.ErrUnexpectedMessageType if m is not
// a gRPC-generated reputation.AnnounceIntermediateResultResponse message.
func (x *AnnounceIntermediateResultResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*reputation.AnnounceIntermediateResultResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		x.body = nil
	} else {
		if x.body == nil {
			x.body = new(AnnounceIntermediateResultResponseBody)
		}

		err = x.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return x.ResponseHeaders.FromMessage(v)
}
