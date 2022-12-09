package subnettest

import (
	refstest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/subnet"
)

func GenerateSubnetInfo(empty bool) *subnet.Info {
	m := new(subnet.Info)

	if !empty {
		m.SetID(refstest.GenerateSubnetID(false))
		m.SetOwner(refstest.GenerateOwnerID(false))
	}

	return m
}
