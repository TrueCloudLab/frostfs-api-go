package reputationtest

import (
	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/reputation"
	sessiontest "github.com/TrueCloudLab/frostfs-api-go/v2/session/test"
)

func GeneratePeerID(empty bool) *reputation.PeerID {
	m := new(reputation.PeerID)

	if !empty {
		m.SetPublicKey([]byte{1, 2, 3})
	}

	return m
}

func GenerateTrust(empty bool) *reputation.Trust {
	m := new(reputation.Trust)

	if !empty {
		m.SetValue(1)
		m.SetPeer(GeneratePeerID(false))
	}

	return m
}

func GeneratePeerToPeerTrust(empty bool) *reputation.PeerToPeerTrust {
	m := new(reputation.PeerToPeerTrust)

	if !empty {
		m.SetTrustingPeer(GeneratePeerID(false))
		m.SetTrust(GenerateTrust(false))
	}

	return m
}

func GenerateGlobalTrustBody(empty bool) *reputation.GlobalTrustBody {
	m := new(reputation.GlobalTrustBody)

	if !empty {
		m.SetManager(GeneratePeerID(false))
		m.SetTrust(GenerateTrust(false))
	}

	return m
}

func GenerateGlobalTrust(empty bool) *reputation.GlobalTrust {
	m := new(reputation.GlobalTrust)

	if !empty {
		m.SetVersion(refstest.GenerateVersion(false))
		m.SetBody(GenerateGlobalTrustBody(false))
		m.SetSignature(refstest.GenerateSignature(empty))
	}

	return m
}

func GenerateTrusts(empty bool) []reputation.Trust {
	var res []reputation.Trust

	if !empty {
		res = append(res,
			*GenerateTrust(false),
			*GenerateTrust(false),
		)
	}

	return res
}

func GenerateAnnounceLocalTrustRequestBody(empty bool) *reputation.AnnounceLocalTrustRequestBody {
	m := new(reputation.AnnounceLocalTrustRequestBody)

	if !empty {
		m.SetEpoch(13)
		m.SetTrusts(GenerateTrusts(false))
	}

	return m
}

func GenerateAnnounceLocalTrustRequest(empty bool) *reputation.AnnounceLocalTrustRequest {
	m := new(reputation.AnnounceLocalTrustRequest)

	if !empty {
		m.SetBody(GenerateAnnounceLocalTrustRequestBody(false))
		m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
		m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))
	}

	return m
}

func GenerateAnnounceLocalTrustResponseBody(empty bool) *reputation.AnnounceLocalTrustResponseBody {
	m := new(reputation.AnnounceLocalTrustResponseBody)

	return m
}

func GenerateAnnounceLocalTrustResponse(empty bool) *reputation.AnnounceLocalTrustResponse {
	m := new(reputation.AnnounceLocalTrustResponse)

	if !empty {
		m.SetBody(GenerateAnnounceLocalTrustResponseBody(false))
		m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
		m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))
	}

	return m
}

func GenerateAnnounceIntermediateResultRequestBody(empty bool) *reputation.AnnounceIntermediateResultRequestBody {
	m := new(reputation.AnnounceIntermediateResultRequestBody)

	if !empty {
		m.SetEpoch(123)
		m.SetIteration(564)
		m.SetTrust(GeneratePeerToPeerTrust(false))
	}

	return m
}

func GenerateAnnounceIntermediateResultRequest(empty bool) *reputation.AnnounceIntermediateResultRequest {
	m := new(reputation.AnnounceIntermediateResultRequest)

	if !empty {
		m.SetBody(GenerateAnnounceIntermediateResultRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateAnnounceIntermediateResultResponseBody(empty bool) *reputation.AnnounceIntermediateResultResponseBody {
	m := new(reputation.AnnounceIntermediateResultResponseBody)

	return m
}

func GenerateAnnounceIntermediateResultResponse(empty bool) *reputation.AnnounceIntermediateResultResponse {
	m := new(reputation.AnnounceIntermediateResultResponse)

	if !empty {
		m.SetBody(GenerateAnnounceIntermediateResultResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}
