package netmap

import (
	netmap "github.com/TrueCloudLab/frostfs-api-go/v2/netmap/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (f *Filter) ToGRPCMessage() grpc.Message {
	var m *netmap.Filter

	if f != nil {
		m = new(netmap.Filter)

		m.SetKey(f.key)
		m.SetValue(f.value)
		m.SetName(f.name)
		m.SetOp(OperationToGRPCMessage(f.op))
		m.SetFilters(FiltersToGRPC(f.filters))
	}

	return m
}

func (f *Filter) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.Filter)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	f.filters, err = FiltersFromGRPC(v.GetFilters())
	if err != nil {
		return err
	}

	f.key = v.GetKey()
	f.value = v.GetValue()
	f.name = v.GetName()
	f.op = OperationFromGRPCMessage(v.GetOp())

	return nil
}

func FiltersToGRPC(fs []Filter) (res []*netmap.Filter) {
	if fs != nil {
		res = make([]*netmap.Filter, 0, len(fs))

		for i := range fs {
			res = append(res, fs[i].ToGRPCMessage().(*netmap.Filter))
		}
	}

	return
}

func FiltersFromGRPC(fs []*netmap.Filter) (res []Filter, err error) {
	if fs != nil {
		res = make([]Filter, len(fs))

		for i := range fs {
			if fs[i] != nil {
				err = res[i].FromGRPCMessage(fs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (s *Selector) ToGRPCMessage() grpc.Message {
	var m *netmap.Selector

	if s != nil {
		m = new(netmap.Selector)

		m.SetName(s.name)
		m.SetAttribute(s.attribute)
		m.SetFilter(s.filter)
		m.SetCount(s.count)
		m.SetClause(ClauseToGRPCMessage(s.clause))
	}

	return m
}

func (s *Selector) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.Selector)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	s.name = v.GetName()
	s.attribute = v.GetAttribute()
	s.filter = v.GetFilter()
	s.count = v.GetCount()
	s.clause = ClauseFromGRPCMessage(v.GetClause())

	return nil
}

func SelectorsToGRPC(ss []Selector) (res []*netmap.Selector) {
	if ss != nil {
		res = make([]*netmap.Selector, 0, len(ss))

		for i := range ss {
			res = append(res, ss[i].ToGRPCMessage().(*netmap.Selector))
		}
	}

	return
}

func SelectorsFromGRPC(ss []*netmap.Selector) (res []Selector, err error) {
	if ss != nil {
		res = make([]Selector, len(ss))

		for i := range ss {
			if ss[i] != nil {
				err = res[i].FromGRPCMessage(ss[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (r *Replica) ToGRPCMessage() grpc.Message {
	var m *netmap.Replica

	if r != nil {
		m = new(netmap.Replica)

		m.SetSelector(r.selector)
		m.SetCount(r.count)
	}

	return m
}

func (r *Replica) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.Replica)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	r.selector = v.GetSelector()
	r.count = v.GetCount()

	return nil
}

func ReplicasToGRPC(rs []Replica) (res []*netmap.Replica) {
	if rs != nil {
		res = make([]*netmap.Replica, 0, len(rs))

		for i := range rs {
			res = append(res, rs[i].ToGRPCMessage().(*netmap.Replica))
		}
	}

	return
}

func ReplicasFromGRPC(rs []*netmap.Replica) (res []Replica, err error) {
	if rs != nil {
		res = make([]Replica, len(rs))

		for i := range rs {
			if rs[i] != nil {
				err = res[i].FromGRPCMessage(rs[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (p *PlacementPolicy) ToGRPCMessage() grpc.Message {
	var m *netmap.PlacementPolicy

	if p != nil {
		m = new(netmap.PlacementPolicy)

		m.SetFilters(FiltersToGRPC(p.filters))
		m.SetSelectors(SelectorsToGRPC(p.selectors))
		m.SetReplicas(ReplicasToGRPC(p.replicas))
		m.SetContainerBackupFactor(p.backupFactor)
		m.SetSubnetID(p.subnetID.ToGRPCMessage().(*refsGRPC.SubnetID))
	}

	return m
}

func (p *PlacementPolicy) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.PlacementPolicy)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	p.filters, err = FiltersFromGRPC(v.GetFilters())
	if err != nil {
		return err
	}

	p.selectors, err = SelectorsFromGRPC(v.GetSelectors())
	if err != nil {
		return err
	}

	p.replicas, err = ReplicasFromGRPC(v.GetReplicas())
	if err != nil {
		return err
	}

	subnetID := v.GetSubnetId()
	if subnetID == nil {
		p.subnetID = nil
	} else {
		if p.subnetID == nil {
			p.subnetID = new(refs.SubnetID)
		}

		err = p.subnetID.FromGRPCMessage(subnetID)
		if err != nil {
			return err
		}
	}

	p.backupFactor = v.GetContainerBackupFactor()

	return nil
}

func ClauseToGRPCMessage(n Clause) netmap.Clause {
	return netmap.Clause(n)
}

func ClauseFromGRPCMessage(n netmap.Clause) Clause {
	return Clause(n)
}

func OperationToGRPCMessage(n Operation) netmap.Operation {
	return netmap.Operation(n)
}

func OperationFromGRPCMessage(n netmap.Operation) Operation {
	return Operation(n)
}

func NodeStateToGRPCMessage(n NodeState) netmap.NodeInfo_State {
	return netmap.NodeInfo_State(n)
}

func NodeStateFromRPCMessage(n netmap.NodeInfo_State) NodeState {
	return NodeState(n)
}

func (a *Attribute) ToGRPCMessage() grpc.Message {
	var m *netmap.NodeInfo_Attribute

	if a != nil {
		m = new(netmap.NodeInfo_Attribute)

		m.SetKey(a.key)
		m.SetValue(a.value)
		m.SetParents(a.parents)
	}

	return m
}

func (a *Attribute) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NodeInfo_Attribute)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	a.key = v.GetKey()
	a.value = v.GetValue()
	a.parents = v.GetParents()

	return nil
}

func AttributesToGRPC(as []Attribute) (res []*netmap.NodeInfo_Attribute) {
	if as != nil {
		res = make([]*netmap.NodeInfo_Attribute, 0, len(as))

		for i := range as {
			res = append(res, as[i].ToGRPCMessage().(*netmap.NodeInfo_Attribute))
		}
	}

	return
}

func AttributesFromGRPC(as []*netmap.NodeInfo_Attribute) (res []Attribute, err error) {
	if as != nil {
		res = make([]Attribute, len(as))

		for i := range as {
			if as[i] != nil {
				err = res[i].FromGRPCMessage(as[i])
				if err != nil {
					return
				}
			}
		}
	}

	return
}

func (ni *NodeInfo) ToGRPCMessage() grpc.Message {
	var m *netmap.NodeInfo

	if ni != nil {
		m = new(netmap.NodeInfo)

		m.SetPublicKey(ni.publicKey)
		m.SetAddresses(ni.addresses)
		m.SetState(NodeStateToGRPCMessage(ni.state))
		m.SetAttributes(AttributesToGRPC(ni.attributes))
	}

	return m
}

func (ni *NodeInfo) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NodeInfo)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	ni.attributes, err = AttributesFromGRPC(v.GetAttributes())
	if err != nil {
		return err
	}

	ni.publicKey = v.GetPublicKey()
	ni.addresses = v.GetAddresses()
	ni.state = NodeStateFromRPCMessage(v.GetState())

	return nil
}

func (l *LocalNodeInfoRequestBody) ToGRPCMessage() grpc.Message {
	var m *netmap.LocalNodeInfoRequest_Body

	if l != nil {
		m = new(netmap.LocalNodeInfoRequest_Body)
	}

	return m
}

func (l *LocalNodeInfoRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.LocalNodeInfoRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	return nil
}

func (l *LocalNodeInfoRequest) ToGRPCMessage() grpc.Message {
	var m *netmap.LocalNodeInfoRequest

	if l != nil {
		m = new(netmap.LocalNodeInfoRequest)

		m.SetBody(l.body.ToGRPCMessage().(*netmap.LocalNodeInfoRequest_Body))
		l.RequestHeaders.ToMessage(m)
	}

	return m
}

func (l *LocalNodeInfoRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.LocalNodeInfoRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		l.body = nil
	} else {
		if l.body == nil {
			l.body = new(LocalNodeInfoRequestBody)
		}

		err = l.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return l.RequestHeaders.FromMessage(v)
}

func (l *LocalNodeInfoResponseBody) ToGRPCMessage() grpc.Message {
	var m *netmap.LocalNodeInfoResponse_Body

	if l != nil {
		m = new(netmap.LocalNodeInfoResponse_Body)

		m.SetVersion(l.version.ToGRPCMessage().(*refsGRPC.Version))
		m.SetNodeInfo(l.nodeInfo.ToGRPCMessage().(*netmap.NodeInfo))
	}

	return m
}

func (l *LocalNodeInfoResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.LocalNodeInfoResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	version := v.GetVersion()
	if version == nil {
		l.version = nil
	} else {
		if l.version == nil {
			l.version = new(refs.Version)
		}

		err = l.version.FromGRPCMessage(version)
		if err != nil {
			return err
		}
	}

	nodeInfo := v.GetNodeInfo()
	if nodeInfo == nil {
		l.nodeInfo = nil
	} else {
		if l.nodeInfo == nil {
			l.nodeInfo = new(NodeInfo)
		}

		err = l.nodeInfo.FromGRPCMessage(nodeInfo)
	}

	return err
}

func (l *LocalNodeInfoResponse) ToGRPCMessage() grpc.Message {
	var m *netmap.LocalNodeInfoResponse

	if l != nil {
		m = new(netmap.LocalNodeInfoResponse)

		m.SetBody(l.body.ToGRPCMessage().(*netmap.LocalNodeInfoResponse_Body))
		l.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (l *LocalNodeInfoResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.LocalNodeInfoResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		l.body = nil
	} else {
		if l.body == nil {
			l.body = new(LocalNodeInfoResponseBody)
		}

		err = l.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return l.ResponseHeaders.FromMessage(v)
}

func (x *NetworkParameter) ToGRPCMessage() grpc.Message {
	var m *netmap.NetworkConfig_Parameter

	if x != nil {
		m = new(netmap.NetworkConfig_Parameter)

		m.SetKey(x.k)
		m.SetValue(x.v)
	}

	return m
}

func (x *NetworkParameter) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetworkConfig_Parameter)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	x.k = v.GetKey()
	x.v = v.GetValue()

	return nil
}

func (x *NetworkConfig) ToGRPCMessage() grpc.Message {
	var m *netmap.NetworkConfig

	if x != nil {
		m = new(netmap.NetworkConfig)

		var ps []*netmap.NetworkConfig_Parameter

		if ln := len(x.ps); ln > 0 {
			ps = make([]*netmap.NetworkConfig_Parameter, 0, ln)

			for i := 0; i < ln; i++ {
				ps = append(ps, x.ps[i].ToGRPCMessage().(*netmap.NetworkConfig_Parameter))
			}
		}

		m.SetParameters(ps)
	}

	return m
}

func (x *NetworkConfig) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetworkConfig)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var (
		ps   []NetworkParameter
		psV2 = v.GetParameters()
	)

	if psV2 != nil {
		ln := len(psV2)

		ps = make([]NetworkParameter, ln)

		for i := 0; i < ln; i++ {
			if psV2[i] != nil {
				if err := ps[i].FromGRPCMessage(psV2[i]); err != nil {
					return err
				}
			}
		}
	}

	x.ps = ps

	return nil
}

func (i *NetworkInfo) ToGRPCMessage() grpc.Message {
	var m *netmap.NetworkInfo

	if i != nil {
		m = new(netmap.NetworkInfo)

		m.SetMagicNumber(i.magicNum)
		m.SetCurrentEpoch(i.curEpoch)
		m.SetMsPerBlock(i.msPerBlock)
		m.SetNetworkConfig(i.netCfg.ToGRPCMessage().(*netmap.NetworkConfig))
	}

	return m
}

func (i *NetworkInfo) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetworkInfo)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	netCfg := v.GetNetworkConfig()
	if netCfg == nil {
		i.netCfg = nil
	} else {
		if i.netCfg == nil {
			i.netCfg = new(NetworkConfig)
		}

		err = i.netCfg.FromGRPCMessage(netCfg)
		if err != nil {
			return err
		}
	}

	i.magicNum = v.GetMagicNumber()
	i.curEpoch = v.GetCurrentEpoch()
	i.msPerBlock = v.GetMsPerBlock()

	return nil
}

func (l *NetworkInfoRequestBody) ToGRPCMessage() grpc.Message {
	var m *netmap.NetworkInfoRequest_Body

	if l != nil {
		m = new(netmap.NetworkInfoRequest_Body)
	}

	return m
}

func (l *NetworkInfoRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetworkInfoRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	return nil
}

func (l *NetworkInfoRequest) ToGRPCMessage() grpc.Message {
	var m *netmap.NetworkInfoRequest

	if l != nil {
		m = new(netmap.NetworkInfoRequest)

		m.SetBody(l.body.ToGRPCMessage().(*netmap.NetworkInfoRequest_Body))
		l.RequestHeaders.ToMessage(m)
	}

	return m
}

func (l *NetworkInfoRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetworkInfoRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		l.body = nil
	} else {
		if l.body == nil {
			l.body = new(NetworkInfoRequestBody)
		}

		err = l.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return l.RequestHeaders.FromMessage(v)
}

func (i *NetworkInfoResponseBody) ToGRPCMessage() grpc.Message {
	var m *netmap.NetworkInfoResponse_Body

	if i != nil {
		m = new(netmap.NetworkInfoResponse_Body)

		m.SetNetworkInfo(i.netInfo.ToGRPCMessage().(*netmap.NetworkInfo))
	}

	return m
}

func (i *NetworkInfoResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetworkInfoResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	netInfo := v.GetNetworkInfo()
	if netInfo == nil {
		i.netInfo = nil
	} else {
		if i.netInfo == nil {
			i.netInfo = new(NetworkInfo)
		}

		err = i.netInfo.FromGRPCMessage(netInfo)
	}

	return err
}

func (l *NetworkInfoResponse) ToGRPCMessage() grpc.Message {
	var m *netmap.NetworkInfoResponse

	if l != nil {
		m = new(netmap.NetworkInfoResponse)

		m.SetBody(l.body.ToGRPCMessage().(*netmap.NetworkInfoResponse_Body))
		l.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (l *NetworkInfoResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetworkInfoResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		l.body = nil
	} else {
		if l.body == nil {
			l.body = new(NetworkInfoResponseBody)
		}

		err = l.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return l.ResponseHeaders.FromMessage(v)
}

func (x *NetMap) ToGRPCMessage() grpc.Message {
	var m *netmap.Netmap

	if x != nil {
		m = new(netmap.Netmap)

		m.SetEpoch(x.epoch)

		if x.nodes != nil {
			nodes := make([]*netmap.NodeInfo, len(x.nodes))

			for i := range x.nodes {
				nodes[i] = x.nodes[i].ToGRPCMessage().(*netmap.NodeInfo)
			}

			m.SetNodes(nodes)
		}
	}

	return m
}

func (x *NetMap) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.Netmap)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	nodes := v.GetNodes()
	if nodes == nil {
		x.nodes = nil
	} else {
		x.nodes = make([]NodeInfo, len(nodes))

		for i := range nodes {
			err = x.nodes[i].FromGRPCMessage(nodes[i])
			if err != nil {
				return err
			}
		}
	}

	x.epoch = v.GetEpoch()

	return nil
}

func (x *SnapshotRequestBody) ToGRPCMessage() grpc.Message {
	var m *netmap.NetmapSnapshotRequest_Body

	if x != nil {
		m = new(netmap.NetmapSnapshotRequest_Body)
	}

	return m
}

func (x *SnapshotRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetmapSnapshotRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	return nil
}

func (x *SnapshotRequest) ToGRPCMessage() grpc.Message {
	var m *netmap.NetmapSnapshotRequest

	if x != nil {
		m = new(netmap.NetmapSnapshotRequest)

		m.SetBody(x.body.ToGRPCMessage().(*netmap.NetmapSnapshotRequest_Body))
		x.RequestHeaders.ToMessage(m)
	}

	return m
}

func (x *SnapshotRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetmapSnapshotRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		x.body = nil
	} else {
		if x.body == nil {
			x.body = new(SnapshotRequestBody)
		}

		err = x.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return x.RequestHeaders.FromMessage(v)
}

func (x *SnapshotResponseBody) ToGRPCMessage() grpc.Message {
	var m *netmap.NetmapSnapshotResponse_Body

	if x != nil {
		m = new(netmap.NetmapSnapshotResponse_Body)

		m.SetNetmap(x.netMap.ToGRPCMessage().(*netmap.Netmap))
	}

	return m
}

func (x *SnapshotResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetmapSnapshotResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	netMap := v.GetNetmap()
	if netMap == nil {
		x.netMap = nil
	} else {
		if x.netMap == nil {
			x.netMap = new(NetMap)
		}

		err = x.netMap.FromGRPCMessage(netMap)
	}

	return err
}

func (x *SnapshotResponse) ToGRPCMessage() grpc.Message {
	var m *netmap.NetmapSnapshotResponse

	if x != nil {
		m = new(netmap.NetmapSnapshotResponse)

		m.SetBody(x.body.ToGRPCMessage().(*netmap.NetmapSnapshotResponse_Body))
		x.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (x *SnapshotResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*netmap.NetmapSnapshotResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		x.body = nil
	} else {
		if x.body == nil {
			x.body = new(SnapshotResponseBody)
		}

		err = x.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return x.ResponseHeaders.FromMessage(v)
}
