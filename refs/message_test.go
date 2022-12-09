package refs_test

import (
	"testing"

	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	messagetest "github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message/test"
)

func TestMessageConvert(t *testing.T) {
	messagetest.TestRPCMessage(t,
		func(empty bool) message.Message { return refstest.GenerateOwnerID(empty) },
		func(empty bool) message.Message { return refstest.GenerateObjectID(empty) },
		func(empty bool) message.Message { return refstest.GenerateContainerID(empty) },
		func(empty bool) message.Message { return refstest.GenerateAddress(empty) },
		func(empty bool) message.Message { return refstest.GenerateChecksum(empty) },
		func(empty bool) message.Message { return refstest.GenerateSignature(empty) },
		func(empty bool) message.Message { return refstest.GenerateVersion(empty) },
		func(empty bool) message.Message { return refstest.GenerateSubnetID(empty) },
	)
}
