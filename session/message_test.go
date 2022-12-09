package session_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	rpctest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
	sessiontest "github.com/TrueCloudLab/frostfs-api-go/v2/session/test"
)

func TestMessageConvert(t *testing.T) {
	rpctest.TestRPCMessage(t,
		func(empty bool) message.Message { return sessiontest.GenerateCreateRequestBody(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateCreateRequest(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateCreateResponseBody(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateCreateResponse(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateTokenLifetime(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateXHeader(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateSessionTokenBody(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateSessionToken(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateRequestMetaHeader(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateRequestVerificationHeader(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateResponseMetaHeader(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateResponseVerificationHeader(empty) },
		func(empty bool) message.Message { return sessiontest.GenerateContainerSessionContext(empty) },
	)
}
