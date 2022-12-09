package netmaptest

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/netmap"
	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	sessiontest "github.com/TrueCloudLab/frostfs-api-go/v2/session/test"
)

func GenerateFilter(empty bool) *netmap.Filter {
	return generateFilter(empty, true)
}

func generateFilter(empty, withSub bool) *netmap.Filter {
	m := new(netmap.Filter)

	if !empty {
		m.SetKey("filter key")
		m.SetValue("filter value")
		m.SetName("filter name")
		m.SetOp(1)

		if withSub {
			m.SetFilters([]netmap.Filter{
				*generateFilter(empty, false),
				*generateFilter(empty, false),
			})
		}
	}

	return m
}

func GenerateFilters(empty bool) []netmap.Filter {
	var res []netmap.Filter

	if !empty {
		res = append(res,
			*GenerateFilter(false),
			*GenerateFilter(false),
		)
	}

	return res
}

func GenerateSelector(empty bool) *netmap.Selector {
	m := new(netmap.Selector)

	if !empty {
		m.SetCount(66)
		m.SetAttribute("selector attribute")
		m.SetFilter("select filter")
		m.SetName("select name")
		m.SetClause(1)
	}

	return m
}

func GenerateSelectors(empty bool) []netmap.Selector {
	var res []netmap.Selector

	if !empty {
		res = append(res,
			*GenerateSelector(false),
			*GenerateSelector(false),
		)
	}

	return res
}

func GenerateReplica(empty bool) *netmap.Replica {
	m := new(netmap.Replica)

	if !empty {
		m.SetCount(42)
		m.SetSelector("replica selector")
	}

	return m
}

func GenerateReplicas(empty bool) []netmap.Replica {
	var res []netmap.Replica

	if !empty {
		res = append(res,
			*GenerateReplica(false),
			*GenerateReplica(false),
		)
	}

	return res
}

func GeneratePlacementPolicy(empty bool) *netmap.PlacementPolicy {
	m := new(netmap.PlacementPolicy)

	if !empty {
		m.SetContainerBackupFactor(322)
		m.SetFilters(GenerateFilters(false))
		m.SetSelectors(GenerateSelectors(false))
		m.SetReplicas(GenerateReplicas(false))
		m.SetSubnetID(refstest.GenerateSubnetID(false))
	}

	return m
}

func GenerateAttribute(empty bool) *netmap.Attribute {
	m := new(netmap.Attribute)

	if !empty {
		m.SetKey("attribute key")
		m.SetValue("attribute val")
	}

	return m
}

func GenerateAttributes(empty bool) []netmap.Attribute {
	var res []netmap.Attribute

	if !empty {
		res = append(res,
			*GenerateAttribute(false),
			*GenerateAttribute(false),
		)
	}

	return res
}

func GenerateNodeInfo(empty bool) *netmap.NodeInfo {
	m := new(netmap.NodeInfo)

	if !empty {
		m.SetAddresses("node address", "node address 2")
		m.SetPublicKey([]byte{1, 2, 3})
		m.SetState(33)
		m.SetAttributes(GenerateAttributes(empty))
	}

	return m
}

func GenerateLocalNodeInfoRequestBody(empty bool) *netmap.LocalNodeInfoRequestBody {
	m := new(netmap.LocalNodeInfoRequestBody)

	return m
}

func GenerateLocalNodeInfoRequest(empty bool) *netmap.LocalNodeInfoRequest {
	m := new(netmap.LocalNodeInfoRequest)

	if !empty {
		m.SetBody(GenerateLocalNodeInfoRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateLocalNodeInfoResponseBody(empty bool) *netmap.LocalNodeInfoResponseBody {
	m := new(netmap.LocalNodeInfoResponseBody)

	if !empty {
		m.SetNodeInfo(GenerateNodeInfo(false))
	}

	m.SetVersion(refstest.GenerateVersion(empty))

	return m
}

func GenerateLocalNodeInfoResponse(empty bool) *netmap.LocalNodeInfoResponse {
	m := new(netmap.LocalNodeInfoResponse)

	if !empty {
		m.SetBody(GenerateLocalNodeInfoResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateNetworkParameter(empty bool) *netmap.NetworkParameter {
	m := new(netmap.NetworkParameter)

	if !empty {
		m.SetKey([]byte("key"))
		m.SetValue([]byte("value"))
	}

	return m
}

func GenerateNetworkConfig(empty bool) *netmap.NetworkConfig {
	m := new(netmap.NetworkConfig)

	if !empty {
		m.SetParameters(
			*GenerateNetworkParameter(empty),
			*GenerateNetworkParameter(empty),
		)
	}

	return m
}

func GenerateNetworkInfo(empty bool) *netmap.NetworkInfo {
	m := new(netmap.NetworkInfo)

	if !empty {
		m.SetMagicNumber(228)
		m.SetCurrentEpoch(666)
		m.SetMsPerBlock(5678)
		m.SetNetworkConfig(GenerateNetworkConfig(empty))
	}

	return m
}

func GenerateNetworkInfoRequestBody(empty bool) *netmap.NetworkInfoRequestBody {
	m := new(netmap.NetworkInfoRequestBody)

	return m
}

func GenerateNetworkInfoRequest(empty bool) *netmap.NetworkInfoRequest {
	m := new(netmap.NetworkInfoRequest)

	if !empty {
		m.SetBody(GenerateNetworkInfoRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateNetworkInfoResponseBody(empty bool) *netmap.NetworkInfoResponseBody {
	m := new(netmap.NetworkInfoResponseBody)

	if !empty {
		m.SetNetworkInfo(GenerateNetworkInfo(false))
	}

	return m
}

func GenerateNetworkInfoResponse(empty bool) *netmap.NetworkInfoResponse {
	m := new(netmap.NetworkInfoResponse)

	if !empty {
		m.SetBody(GenerateNetworkInfoResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateNetMap(empty bool) *netmap.NetMap {
	m := new(netmap.NetMap)

	if !empty {
		m.SetEpoch(987)
		m.SetNodes([]netmap.NodeInfo{
			*GenerateNodeInfo(false),
			*GenerateNodeInfo(false),
		})
	}

	return m
}

func GenerateSnapshotRequestBody(_ bool) *netmap.SnapshotRequestBody {
	return new(netmap.SnapshotRequestBody)
}

func GenerateSnapshotRequest(empty bool) *netmap.SnapshotRequest {
	m := new(netmap.SnapshotRequest)

	if !empty {
		m.SetBody(GenerateSnapshotRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateSnapshotResponseBody(empty bool) *netmap.SnapshotResponseBody {
	m := new(netmap.SnapshotResponseBody)

	if !empty {
		m.SetNetMap(GenerateNetMap(false))
	}

	return m
}

func GenerateSnapshotResponse(empty bool) *netmap.SnapshotResponse {
	m := new(netmap.SnapshotResponse)

	if !empty {
		m.SetBody(GenerateSnapshotResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}
