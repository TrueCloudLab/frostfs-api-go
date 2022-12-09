package audittest

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/audit"
	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
)

func GenerateDataAuditResult(empty bool) *audit.DataAuditResult {
	m := new(audit.DataAuditResult)

	if !empty {
		m.SetPublicKey([]byte{1, 2, 3})
		m.SetAuditEpoch(13)
		m.SetHit(100)
		m.SetMiss(200)
		m.SetFail(300)
		m.SetComplete(true)
		m.SetPassNodes([][]byte{{1}, {2}})
		m.SetFailNodes([][]byte{{3}, {4}})
		m.SetRequests(666)
		m.SetRetries(777)
		m.SetVersion(refstest.GenerateVersion(false))
		m.SetContainerID(refstest.GenerateContainerID(false))
		m.SetPassSG(refstest.GenerateObjectIDs(false))
		m.SetFailSG(refstest.GenerateObjectIDs(false))
	}

	return m
}
