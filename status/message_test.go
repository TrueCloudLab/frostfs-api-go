package status_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	messagetest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
	statustest "github.com/TrueCloudLab/frostfs-api-go/v2/status/test"
)

func TestMessageConvert(t *testing.T) {
	messagetest.TestRPCMessage(t,
		func(empty bool) message.Message { return statustest.Detail(empty) },
		func(empty bool) message.Message { return statustest.Status(empty) },
	)
}
