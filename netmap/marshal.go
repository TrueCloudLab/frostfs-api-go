package netmap

import (
	netmap "github.com/TrueCloudLab/frostfs-api-go/v2/netmap/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	protoutil "github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	nameFilterField    = 1
	keyFilterField     = 2
	opFilterField      = 3
	valueFilterField   = 4
	filtersFilterField = 5

	nameSelectorField      = 1
	countSelectorField     = 2
	clauseSelectorField    = 3
	attributeSelectorField = 4
	filterSelectorField    = 5

	countReplicaField    = 1
	selectorReplicaField = 2

	replicasPolicyField  = 1
	backupPolicyField    = 2
	selectorsPolicyField = 3
	filtersPolicyField   = 4
	subnetIDPolicyField  = 5

	keyAttributeField     = 1
	valueAttributeField   = 2
	parentsAttributeField = 3

	keyNodeInfoField        = 1
	addressNodeInfoField    = 2
	attributesNodeInfoField = 3
	stateNodeInfoField      = 4

	versionInfoResponseBodyField = 1
	nodeInfoResponseBodyField    = 2
)

func (f *Filter) StableMarshal(buf []byte) []byte {
	if f == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, f.StableSize())
	}

	var offset int

	offset += protoutil.StringMarshal(nameFilterField, buf[offset:], f.name)
	offset += protoutil.StringMarshal(keyFilterField, buf[offset:], f.key)
	offset += protoutil.EnumMarshal(opFilterField, buf[offset:], int32(f.op))
	offset += protoutil.StringMarshal(valueFilterField, buf[offset:], f.value)

	for i := range f.filters {
		offset += protoutil.NestedStructureMarshal(filtersFilterField, buf[offset:], &f.filters[i])
	}

	return buf
}

func (f *Filter) StableSize() (size int) {
	size += protoutil.StringSize(nameFilterField, f.name)
	size += protoutil.StringSize(keyFilterField, f.key)
	size += protoutil.EnumSize(opFilterField, int32(f.op))
	size += protoutil.StringSize(valueFilterField, f.value)
	for i := range f.filters {
		size += protoutil.NestedStructureSize(filtersFilterField, &f.filters[i])
	}

	return size
}

func (f *Filter) Unmarshal(data []byte) error {
	return message.Unmarshal(f, data, new(netmap.Filter))
}

func (s *Selector) StableMarshal(buf []byte) []byte {
	if s == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, s.StableSize())
	}

	var offset int

	offset += protoutil.StringMarshal(nameSelectorField, buf[offset:], s.name)
	offset += protoutil.UInt32Marshal(countSelectorField, buf[offset:], s.count)
	offset += protoutil.EnumMarshal(clauseSelectorField, buf[offset:], int32(s.clause))
	offset += protoutil.StringMarshal(attributeSelectorField, buf[offset:], s.attribute)
	protoutil.StringMarshal(filterSelectorField, buf[offset:], s.filter)

	return buf
}

func (s *Selector) StableSize() (size int) {
	size += protoutil.StringSize(nameSelectorField, s.name)
	size += protoutil.UInt32Size(countSelectorField, s.count)
	size += protoutil.EnumSize(countSelectorField, int32(s.clause))
	size += protoutil.StringSize(attributeSelectorField, s.attribute)
	size += protoutil.StringSize(filterSelectorField, s.filter)

	return size
}

func (s *Selector) Unmarshal(data []byte) error {
	return message.Unmarshal(s, data, new(netmap.Selector))
}

func (r *Replica) StableMarshal(buf []byte) []byte {
	if r == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, r.StableSize())
	}

	var offset int

	offset += protoutil.UInt32Marshal(countReplicaField, buf[offset:], r.count)
	protoutil.StringMarshal(selectorReplicaField, buf[offset:], r.selector)

	return buf
}

func (r *Replica) StableSize() (size int) {
	size += protoutil.UInt32Size(countReplicaField, r.count)
	size += protoutil.StringSize(selectorReplicaField, r.selector)

	return size
}

func (r *Replica) Unmarshal(data []byte) error {
	return message.Unmarshal(r, data, new(netmap.Replica))
}

func (p *PlacementPolicy) StableMarshal(buf []byte) []byte {
	if p == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, p.StableSize())
	}

	var offset int

	for i := range p.replicas {
		offset += protoutil.NestedStructureMarshal(replicasPolicyField, buf[offset:], &p.replicas[i])
	}

	offset += protoutil.UInt32Marshal(backupPolicyField, buf[offset:], p.backupFactor)

	for i := range p.selectors {
		offset += protoutil.NestedStructureMarshal(selectorsPolicyField, buf[offset:], &p.selectors[i])
	}

	for i := range p.filters {
		offset += protoutil.NestedStructureMarshal(filtersPolicyField, buf[offset:], &p.filters[i])
	}

	protoutil.NestedStructureMarshal(subnetIDPolicyField, buf[offset:], p.subnetID)

	return buf
}

func (p *PlacementPolicy) StableSize() (size int) {
	for i := range p.replicas {
		size += protoutil.NestedStructureSize(replicasPolicyField, &p.replicas[i])
	}

	size += protoutil.UInt32Size(backupPolicyField, p.backupFactor)

	for i := range p.selectors {
		size += protoutil.NestedStructureSize(selectorsPolicyField, &p.selectors[i])
	}

	for i := range p.filters {
		size += protoutil.NestedStructureSize(filtersPolicyField, &p.filters[i])
	}

	size += protoutil.NestedStructureSize(subnetIDPolicyField, p.subnetID)

	return size
}

func (p *PlacementPolicy) Unmarshal(data []byte) error {
	return message.Unmarshal(p, data, new(netmap.PlacementPolicy))
}

func (a *Attribute) StableMarshal(buf []byte) []byte {
	if a == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, a.StableSize())
	}

	var offset int

	offset += protoutil.StringMarshal(keyAttributeField, buf[offset:], a.key)
	offset += protoutil.StringMarshal(valueAttributeField, buf[offset:], a.value)

	for i := range a.parents {
		offset += protoutil.StringMarshal(parentsAttributeField, buf[offset:], a.parents[i])
	}

	return buf
}

func (a *Attribute) StableSize() (size int) {
	if a == nil {
		return 0
	}

	size += protoutil.StringSize(keyAttributeField, a.key)
	size += protoutil.StringSize(valueAttributeField, a.value)

	for i := range a.parents {
		size += protoutil.StringSize(parentsAttributeField, a.parents[i])
	}

	return size
}

func (a *Attribute) Unmarshal(data []byte) error {
	return message.Unmarshal(a, data, new(netmap.NodeInfo_Attribute))
}

func (ni *NodeInfo) StableMarshal(buf []byte) []byte {
	if ni == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, ni.StableSize())
	}

	var offset int

	offset += protoutil.BytesMarshal(keyNodeInfoField, buf[offset:], ni.publicKey)
	offset += protoutil.RepeatedStringMarshal(addressNodeInfoField, buf[offset:], ni.addresses)

	for i := range ni.attributes {
		offset += protoutil.NestedStructureMarshal(attributesNodeInfoField, buf[offset:], &ni.attributes[i])
	}

	protoutil.EnumMarshal(stateNodeInfoField, buf[offset:], int32(ni.state))

	return buf
}

func (ni *NodeInfo) StableSize() (size int) {
	if ni == nil {
		return 0
	}

	size += protoutil.BytesSize(keyNodeInfoField, ni.publicKey)
	size += protoutil.RepeatedStringSize(addressNodeInfoField, ni.addresses)

	for i := range ni.attributes {
		size += protoutil.NestedStructureSize(attributesNodeInfoField, &ni.attributes[i])
	}

	size += protoutil.EnumSize(stateNodeInfoField, int32(ni.state))

	return size
}

func (ni *NodeInfo) Unmarshal(data []byte) error {
	return message.Unmarshal(ni, data, new(netmap.NodeInfo))
}

func (l *LocalNodeInfoRequestBody) StableMarshal(buf []byte) []byte {
	return nil
}

func (l *LocalNodeInfoRequestBody) StableSize() (size int) {
	return 0
}

func (l *LocalNodeInfoRequestBody) Unmarshal([]byte) error {
	return nil
}

func (l *LocalNodeInfoResponseBody) StableMarshal(buf []byte) []byte {
	if l == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, l.StableSize())
	}

	var offset int

	offset += protoutil.NestedStructureMarshal(versionInfoResponseBodyField, buf[offset:], l.version)
	protoutil.NestedStructureMarshal(nodeInfoResponseBodyField, buf[offset:], l.nodeInfo)

	return buf
}

func (l *LocalNodeInfoResponseBody) StableSize() (size int) {
	if l == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(versionInfoResponseBodyField, l.version)
	size += protoutil.NestedStructureSize(nodeInfoResponseBodyField, l.nodeInfo)

	return size
}

func (l *LocalNodeInfoResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(l, data, new(netmap.LocalNodeInfoResponse_Body))
}

const (
	_ = iota
	netPrmKeyFNum
	netPrmValFNum
)

func (x *NetworkParameter) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.BytesMarshal(netPrmKeyFNum, buf[offset:], x.k)
	protoutil.BytesMarshal(netPrmValFNum, buf[offset:], x.v)

	return buf
}

func (x *NetworkParameter) StableSize() (size int) {
	if x == nil {
		return 0
	}

	size += protoutil.BytesSize(netPrmKeyFNum, x.k)
	size += protoutil.BytesSize(netPrmValFNum, x.v)

	return size
}

const (
	_ = iota
	netCfgPrmsFNum
)

func (x *NetworkConfig) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	for i := range x.ps {
		offset += protoutil.NestedStructureMarshal(netCfgPrmsFNum, buf[offset:], &x.ps[i])
	}

	return buf
}

func (x *NetworkConfig) StableSize() (size int) {
	if x == nil {
		return 0
	}

	for i := range x.ps {
		size += protoutil.NestedStructureSize(netCfgPrmsFNum, &x.ps[i])
	}

	return size
}

const (
	_ = iota
	netInfoCurEpochFNum
	netInfoMagicNumFNum
	netInfoMSPerBlockFNum
	netInfoCfgFNum
)

func (i *NetworkInfo) StableMarshal(buf []byte) []byte {
	if i == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, i.StableSize())
	}

	var offset int

	offset += protoutil.UInt64Marshal(netInfoCurEpochFNum, buf[offset:], i.curEpoch)
	offset += protoutil.UInt64Marshal(netInfoMagicNumFNum, buf[offset:], i.magicNum)
	offset += protoutil.Int64Marshal(netInfoMSPerBlockFNum, buf[offset:], i.msPerBlock)
	protoutil.NestedStructureMarshal(netInfoCfgFNum, buf[offset:], i.netCfg)

	return buf
}

func (i *NetworkInfo) StableSize() (size int) {
	if i == nil {
		return 0
	}

	size += protoutil.UInt64Size(netInfoCurEpochFNum, i.curEpoch)
	size += protoutil.UInt64Size(netInfoMagicNumFNum, i.magicNum)
	size += protoutil.Int64Size(netInfoMSPerBlockFNum, i.msPerBlock)
	size += protoutil.NestedStructureSize(netInfoCfgFNum, i.netCfg)

	return size
}

func (i *NetworkInfo) Unmarshal(data []byte) error {
	return message.Unmarshal(i, data, new(netmap.NetworkInfo))
}

func (l *NetworkInfoRequestBody) StableMarshal(buf []byte) []byte {
	return nil
}

func (l *NetworkInfoRequestBody) StableSize() (size int) {
	return 0
}

func (l *NetworkInfoRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(l, data, new(netmap.NetworkInfoRequest_Body))
}

const (
	_ = iota
	netInfoRespBodyNetInfoFNum
)

func (i *NetworkInfoResponseBody) StableMarshal(buf []byte) []byte {
	if i == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, i.StableSize())
	}

	protoutil.NestedStructureMarshal(netInfoRespBodyNetInfoFNum, buf, i.netInfo)

	return buf
}

func (i *NetworkInfoResponseBody) StableSize() (size int) {
	if i == nil {
		return 0
	}

	size += protoutil.NestedStructureSize(netInfoRespBodyNetInfoFNum, i.netInfo)

	return size
}

func (i *NetworkInfoResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(i, data, new(netmap.NetworkInfoResponse_Body))
}

const (
	_ = iota
	fNumNetMapEpoch
	fNumNetMapNodes
)

func (x *NetMap) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	offset := protoutil.UInt64Marshal(fNumNetMapEpoch, buf, x.epoch)

	for i := range x.nodes {
		offset += protoutil.NestedStructureMarshal(fNumNetMapNodes, buf[offset:], &x.nodes[i])
	}

	return buf
}

func (x *NetMap) StableSize() (size int) {
	if x != nil {
		size = protoutil.UInt64Size(fNumNetMapEpoch, x.epoch)

		for i := range x.nodes {
			size += protoutil.NestedStructureSize(fNumNetMapNodes, &x.nodes[i])
		}
	}

	return
}

func (x *SnapshotRequestBody) StableMarshal([]byte) []byte {
	return nil
}

func (x *SnapshotRequestBody) StableSize() int {
	return 0
}

const (
	_ = iota
	fNumSnapshotResponseBodyNetMap
)

func (x *SnapshotResponseBody) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	protoutil.NestedStructureMarshal(fNumSnapshotResponseBodyNetMap, buf, x.netMap)

	return buf
}

func (x *SnapshotResponseBody) StableSize() (size int) {
	if x != nil {
		size = protoutil.NestedStructureSize(fNumSnapshotResponseBodyNetMap, x.netMap)
	}

	return
}
