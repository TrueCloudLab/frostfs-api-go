package reputation

import (
	reputation "github.com/TrueCloudLab/frostfs-api-go/v2/reputation/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	protoutil "github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	_ = iota
	peerIDPubKeyFNum
)

func (x *PeerID) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	protoutil.BytesMarshal(peerIDPubKeyFNum, buf, x.publicKey)

	return buf
}

func (x *PeerID) StableSize() (size int) {
	size += protoutil.BytesSize(peerIDPubKeyFNum, x.publicKey)

	return
}

func (x *PeerID) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.PeerID))
}

const (
	_ = iota
	trustPeerFNum
	trustValueFNum
)

func (x *Trust) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(trustPeerFNum, buf[offset:], x.peer)
	protoutil.Float64Marshal(trustValueFNum, buf[offset:], x.val)

	return buf
}

func (x *Trust) StableSize() (size int) {
	size += protoutil.NestedStructureSize(trustPeerFNum, x.peer)
	size += protoutil.Float64Size(trustValueFNum, x.val)

	return
}

func (x *Trust) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.Trust))
}

const (
	_ = iota
	p2pTrustTrustingFNum
	p2pTrustValueFNum
)

func (x *PeerToPeerTrust) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(p2pTrustTrustingFNum, buf, x.trusting)
	protoutil.NestedStructureMarshal(p2pTrustValueFNum, buf[offset:], x.trust)

	return buf
}

func (x *PeerToPeerTrust) StableSize() (size int) {
	size += protoutil.NestedStructureSize(p2pTrustTrustingFNum, x.trusting)
	size += protoutil.NestedStructureSize(p2pTrustValueFNum, x.trust)

	return
}

func (x *PeerToPeerTrust) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.PeerToPeerTrust))
}

const (
	_ = iota
	globalTrustBodyManagerFNum
	globalTrustBodyValueFNum
)

func (x *GlobalTrustBody) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(globalTrustBodyManagerFNum, buf, x.manager)
	protoutil.NestedStructureMarshal(globalTrustBodyValueFNum, buf[offset:], x.trust)

	return buf
}

func (x *GlobalTrustBody) StableSize() (size int) {
	size += protoutil.NestedStructureSize(globalTrustBodyManagerFNum, x.manager)
	size += protoutil.NestedStructureSize(globalTrustBodyValueFNum, x.trust)

	return
}

func (x *GlobalTrustBody) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.GlobalTrust_Body))
}

const (
	_ = iota
	globalTrustVersionFNum
	globalTrustBodyFNum
	globalTrustSigFNum
)

func (x *GlobalTrust) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(globalTrustVersionFNum, buf, x.version)
	offset += protoutil.NestedStructureMarshal(globalTrustBodyFNum, buf[offset:], x.body)
	protoutil.NestedStructureMarshal(globalTrustSigFNum, buf[offset:], x.sig)

	return buf
}

func (x *GlobalTrust) StableSize() (size int) {
	size += protoutil.NestedStructureSize(globalTrustVersionFNum, x.version)
	size += protoutil.NestedStructureSize(globalTrustBodyFNum, x.body)
	size += protoutil.NestedStructureSize(globalTrustSigFNum, x.sig)

	return
}

func (x *GlobalTrust) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.GlobalTrust))
}

const (
	_ = iota
	announceLocalTrustBodyEpochFNum
	announceLocalTrustBodyTrustsFNum
)

func (x *AnnounceLocalTrustRequestBody) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.UInt64Marshal(announceLocalTrustBodyEpochFNum, buf[offset:], x.epoch)

	for i := range x.trusts {
		offset += protoutil.NestedStructureMarshal(announceLocalTrustBodyTrustsFNum, buf[offset:], &x.trusts[i])
	}

	return buf
}

func (x *AnnounceLocalTrustRequestBody) StableSize() (size int) {
	size += protoutil.UInt64Size(announceLocalTrustBodyEpochFNum, x.epoch)

	for i := range x.trusts {
		size += protoutil.NestedStructureSize(announceLocalTrustBodyTrustsFNum, &x.trusts[i])
	}

	return
}

func (x *AnnounceLocalTrustRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.AnnounceLocalTrustRequest_Body))
}

func (x *AnnounceLocalTrustResponseBody) StableMarshal(buf []byte) []byte {
	return buf
}

func (x *AnnounceLocalTrustResponseBody) StableSize() int {
	return 0
}

func (x *AnnounceLocalTrustResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.AnnounceLocalTrustResponse_Body))
}

const (
	_ = iota
	announceInterResBodyEpochFNum
	announceInterResBodyIterFNum
	announceInterResBodyTrustFNum
)

func (x *AnnounceIntermediateResultRequestBody) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.UInt64Marshal(announceInterResBodyEpochFNum, buf, x.epoch)
	offset += protoutil.UInt32Marshal(announceInterResBodyIterFNum, buf[offset:], x.iter)
	protoutil.NestedStructureMarshal(announceInterResBodyTrustFNum, buf[offset:], x.trust)

	return buf
}

func (x *AnnounceIntermediateResultRequestBody) StableSize() (size int) {
	size += protoutil.UInt64Size(announceInterResBodyEpochFNum, x.epoch)
	size += protoutil.UInt32Size(announceInterResBodyIterFNum, x.iter)
	size += protoutil.NestedStructureSize(announceInterResBodyTrustFNum, x.trust)

	return
}

func (x *AnnounceIntermediateResultRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.AnnounceIntermediateResultRequest_Body))
}

func (x *AnnounceIntermediateResultResponseBody) StableMarshal(buf []byte) []byte {
	return buf
}

func (x *AnnounceIntermediateResultResponseBody) StableSize() int {
	return 0
}

func (x *AnnounceIntermediateResultResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(reputation.AnnounceIntermediateResultResponse_Body))
}
