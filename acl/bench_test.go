package acl_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/acl"
	aclGrpc "github.com/TrueCloudLab/frostfs-api-go/v2/acl/grpc"
	acltest "github.com/TrueCloudLab/frostfs-api-go/v2/acl/test"
)

func BenchmarkTable_ToGRPCMessage(b *testing.B) {
	const size = 4

	tb := new(acl.Table)
	rs := make([]acl.Record, size)
	for i := range rs {
		fs := make([]acl.HeaderFilter, size)
		for j := range fs {
			fs[j] = *acltest.GenerateFilter(false)
		}
		ts := make([]acl.Target, size)
		for j := range ts {
			ts[j] = *acltest.GenerateTarget(false)
		}

		rs[i].SetFilters(fs)
		rs[i].SetTargets(ts)
	}
	tb.SetRecords(rs)

	raw := tb.ToGRPCMessage()

	b.Run("to grpc message", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			raw := tb.ToGRPCMessage()
			if len(tb.GetRecords()) != len(raw.(*aclGrpc.EACLTable).Records) {
				b.FailNow()
			}
		}
	})
	b.Run("from grpc message", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			tb := new(acl.Table)
			if tb.FromGRPCMessage(raw) != nil {
				b.FailNow()
			}
		}
	})
}
