package netmap

import (
	netmap "github.com/TrueCloudLab/frostfs-api-go/v2/netmap/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (p *PlacementPolicy) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(p)
}

func (p *PlacementPolicy) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(p, data, new(netmap.PlacementPolicy))
}

func (f *Filter) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(f)
}

func (f *Filter) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(f, data, new(netmap.Filter))
}

func (s *Selector) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(s)
}

func (s *Selector) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(s, data, new(netmap.Selector))
}

func (r *Replica) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(r)
}

func (r *Replica) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(r, data, new(netmap.Replica))
}

func (a *Attribute) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(a)
}

func (a *Attribute) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(a, data, new(netmap.NodeInfo_Attribute))
}

func (ni *NodeInfo) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(ni)
}

func (ni *NodeInfo) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(ni, data, new(netmap.NodeInfo))
}

func (i *NetworkInfo) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(i)
}

func (i *NetworkInfo) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(i, data, new(netmap.NetworkInfo))
}
