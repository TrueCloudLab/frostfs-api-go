package container

import (
	netmap "github.com/TrueCloudLab/frostfs-api-go/v2/netmap/grpc"
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
)

// SetKey sets key to the container attribute.
func (m *Container_Attribute) SetKey(v string) {
	m.Key = v
}

// SetValue sets value of the container attribute.
func (m *Container_Attribute) SetValue(v string) {
	m.Value = v
}

// SetOwnerId sets identifier of the container owner,
func (m *Container) SetOwnerId(v *refs.OwnerID) {
	m.OwnerId = v
}

// SetNonce sets nonce of the container structure.
func (m *Container) SetNonce(v []byte) {
	m.Nonce = v
}

// SetBasicAcl sets basic ACL of the container.
func (m *Container) SetBasicAcl(v uint32) {
	m.BasicAcl = v
}

// SetAttributes sets list of the container attributes.
func (m *Container) SetAttributes(v []*Container_Attribute) {
	m.Attributes = v
}

// SetPlacementPolicy sets placement policy of the container.
func (m *Container) SetPlacementPolicy(v *netmap.PlacementPolicy) {
	m.PlacementPolicy = v
}

// SetVersion sets version of the container.
func (m *Container) SetVersion(v *refs.Version) {
	m.Version = v
}
