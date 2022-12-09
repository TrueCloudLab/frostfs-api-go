package audit

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// SetVersion is a Version field setter.
func (x *DataAuditResult) SetVersion(v *refs.Version) {
	x.Version = v
}

// SetAuditEpoch is an AuditEpoch field setter.
func (x *DataAuditResult) SetAuditEpoch(v uint64) {
	x.AuditEpoch = v
}

// SetContainerId is a ContainerId field setter.
func (x *DataAuditResult) SetContainerId(v *refs.ContainerID) {
	x.ContainerId = v
}

// SetPublicKey is a PublicKey field setter.
func (x *DataAuditResult) SetPublicKey(v []byte) {
	x.PublicKey = v
}

// SetComplete is a Complete field setter.
func (x *DataAuditResult) SetComplete(v bool) {
	x.Complete = v
}

// SetRequests is a Requests field setter.
func (x *DataAuditResult) SetRequests(v uint32) {
	x.Requests = v
}

// SetRetries is a Retries field setter.
func (x *DataAuditResult) SetRetries(v uint32) {
	x.Retries = v
}

// SetPassSg is a PassSg field setter.
func (x *DataAuditResult) SetPassSg(v []*refs.ObjectID) {
	x.PassSg = v
}

// SetFailSg is a FailSg field setter.
func (x *DataAuditResult) SetFailSg(v []*refs.ObjectID) {
	x.FailSg = v
}

// SetHit is a Hit field setter.
func (x *DataAuditResult) SetHit(v uint32) {
	x.Hit = v
}

// SetMiss is a Miss field setter.
func (x *DataAuditResult) SetMiss(v uint32) {
	x.Miss = v
}

// SetFail is a Fail field setter.
func (x *DataAuditResult) SetFail(v uint32) {
	x.Fail = v
}

// SetPassNodes is a PassNodes field setter.
func (x *DataAuditResult) SetPassNodes(v [][]byte) {
	x.PassNodes = v
}

// SetFailNodes is a FailNodes field setter.
func (x *DataAuditResult) SetFailNodes(v [][]byte) {
	x.FailNodes = v
}
