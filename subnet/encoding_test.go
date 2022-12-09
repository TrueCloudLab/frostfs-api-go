package subnet_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	messagetest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
	subnettest "github.com/TrueCloudLab/frostfs-api-go/v2/subnet/test"
)

func TestMessageConvert(t *testing.T) {
	messagetest.TestRPCMessage(t,
		func(empty bool) message.Message { return subnettest.GenerateSubnetInfo(empty) },
	)
}
