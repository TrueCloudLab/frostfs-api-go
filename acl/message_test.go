package acl_test

import (
	"testing"

	acltest "github.com/TrueCloudLab/frostfs-api-go/v2/acl/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	messagetest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
)

func TestMessageConvert(t *testing.T) {
	messagetest.TestRPCMessage(t,
		func(empty bool) message.Message { return acltest.GenerateFilter(empty) },
		func(empty bool) message.Message { return acltest.GenerateTarget(empty) },
		func(empty bool) message.Message { return acltest.GenerateRecord(empty) },
		func(empty bool) message.Message { return acltest.GenerateTable(empty) },
		func(empty bool) message.Message { return acltest.GenerateTokenLifetime(empty) },
		func(empty bool) message.Message { return acltest.GenerateBearerTokenBody(empty) },
		func(empty bool) message.Message { return acltest.GenerateBearerToken(empty) },
	)
}
