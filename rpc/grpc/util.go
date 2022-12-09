package grpc

import (
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
)

const methodNameFmt = "/%s/%s"

func toMethodName(p common.CallMethodInfo) string {
	return fmt.Sprintf(methodNameFmt, p.Service, p.Name)
}
