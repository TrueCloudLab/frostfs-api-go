package audit

import (
	audit "github.com/TrueCloudLab/frostfs-api-go/v2/audit/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (a *DataAuditResult) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(a)
}

func (a *DataAuditResult) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(a, data, new(audit.DataAuditResult))
}
