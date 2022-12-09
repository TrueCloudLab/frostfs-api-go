package reputation_test

import (
	"testing"

	reputationtest "github.com/TrueCloudLab/frostfs-api-go/v2/reputation/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	messagetest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
)

func TestMessageConvert(t *testing.T) {
	messagetest.TestRPCMessage(t,
		func(empty bool) message.Message { return reputationtest.GenerateTrust(empty) },
		func(empty bool) message.Message { return reputationtest.GenerateAnnounceLocalTrustRequestBody(empty) },
		func(empty bool) message.Message { return reputationtest.GenerateAnnounceLocalTrustRequest(empty) },
		func(empty bool) message.Message { return reputationtest.GenerateAnnounceLocalTrustResponseBody(empty) },
		func(empty bool) message.Message { return reputationtest.GenerateAnnounceLocalTrustResponse(empty) },
		func(empty bool) message.Message {
			return reputationtest.GenerateAnnounceIntermediateResultRequestBody(empty)
		},
		func(empty bool) message.Message {
			return reputationtest.GenerateAnnounceIntermediateResultRequest(empty)
		},
		func(empty bool) message.Message {
			return reputationtest.GenerateAnnounceIntermediateResultResponseBody(empty)
		},
		func(empty bool) message.Message {
			return reputationtest.GenerateAnnounceIntermediateResultResponse(empty)
		},
		func(empty bool) message.Message { return reputationtest.GenerateGlobalTrustBody(empty) },
		func(empty bool) message.Message { return reputationtest.GenerateGlobalTrust(empty) },
		func(empty bool) message.Message { return reputationtest.GeneratePeerToPeerTrust(empty) },
	)
}
