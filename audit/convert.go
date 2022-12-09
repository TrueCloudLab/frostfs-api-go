package audit

import (
	audit "github.com/TrueCloudLab/frostfs-api-go/v2/audit/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (a *DataAuditResult) ToGRPCMessage() grpc.Message {
	var m *audit.DataAuditResult

	if a != nil {
		m = new(audit.DataAuditResult)

		m.SetAuditEpoch(a.auditEpoch)
		m.SetPublicKey(a.pubKey)
		m.SetContainerId(a.cid.ToGRPCMessage().(*refsGRPC.ContainerID))
		m.SetComplete(a.complete)
		m.SetVersion(a.version.ToGRPCMessage().(*refsGRPC.Version))
		m.SetPassNodes(a.passNodes)
		m.SetFailNodes(a.failNodes)
		m.SetRetries(a.retries)
		m.SetRequests(a.requests)
		m.SetHit(a.hit)
		m.SetMiss(a.miss)
		m.SetFail(a.fail)
		m.SetPassSg(refs.ObjectIDListToGRPCMessage(a.passSG))
		m.SetFailSg(refs.ObjectIDListToGRPCMessage(a.failSG))
	}

	return m
}

func (a *DataAuditResult) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*audit.DataAuditResult)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	cid := v.GetContainerId()
	if cid == nil {
		a.cid = nil
	} else {
		if a.cid == nil {
			a.cid = new(refs.ContainerID)
		}

		err = a.cid.FromGRPCMessage(cid)
		if err != nil {
			return err
		}
	}

	version := v.GetVersion()
	if version == nil {
		a.version = nil
	} else {
		if a.version == nil {
			a.version = new(refs.Version)
		}

		err = a.version.FromGRPCMessage(version)
		if err != nil {
			return err
		}
	}

	a.passSG, err = refs.ObjectIDListFromGRPCMessage(v.GetPassSg())
	if err != nil {
		return err
	}

	a.failSG, err = refs.ObjectIDListFromGRPCMessage(v.GetFailSg())
	if err != nil {
		return err
	}

	a.auditEpoch = v.GetAuditEpoch()
	a.pubKey = v.GetPublicKey()
	a.complete = v.GetComplete()
	a.passNodes = v.GetPassNodes()
	a.failNodes = v.GetFailNodes()
	a.retries = v.GetRetries()
	a.requests = v.GetRequests()
	a.hit = v.GetHit()
	a.miss = v.GetMiss()
	a.fail = v.GetFail()

	return err
}
