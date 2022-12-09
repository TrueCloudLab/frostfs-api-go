package audit_test

import (
	"testing"

	audittest "github.com/TrueCloudLab/frostfs-api-go/v2/audit/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	messagetest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
)

func TestMessageConvert(t *testing.T) {
	messagetest.TestRPCMessage(t,
		func(empty bool) message.Message { return audittest.GenerateDataAuditResult(empty) },
	)
}
