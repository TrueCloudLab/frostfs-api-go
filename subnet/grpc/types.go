package subnet

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// SetID returns identifier of the subnet. Nil arg is equivalent to zero subnet ID.
func (x *SubnetInfo) SetID(id *refs.SubnetID) {
	x.Id = id
}

// SetOwner sets subnet owner's ID in NeoFS system.
func (x *SubnetInfo) SetOwner(id *refs.OwnerID) {
	x.Owner = id
}
