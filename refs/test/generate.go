package refstest

import (
	"math/rand"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
)

func GenerateVersion(empty bool) *refs.Version {
	m := new(refs.Version)

	if !empty {
		m.SetMajor(2)
		m.SetMinor(1)
	}

	return m
}

func GenerateOwnerID(empty bool) *refs.OwnerID {
	m := new(refs.OwnerID)

	if !empty {
		m.SetValue([]byte{1, 2, 3})
	}

	return m
}

func GenerateAddress(empty bool) *refs.Address {
	m := new(refs.Address)

	if !empty {
		m.SetObjectID(GenerateObjectID(false))
		m.SetContainerID(GenerateContainerID(false))
	}

	return m
}

func GenerateObjectID(empty bool) *refs.ObjectID {
	m := new(refs.ObjectID)

	if !empty {
		m.SetValue([]byte{1, 2, 3})
	}

	return m
}

func GenerateObjectIDs(empty bool) []refs.ObjectID {
	var ids []refs.ObjectID

	if !empty {
		ids = append(ids,
			*GenerateObjectID(false),
			*GenerateObjectID(false),
		)
	}

	return ids
}

func GenerateContainerID(empty bool) *refs.ContainerID {
	m := new(refs.ContainerID)

	if !empty {
		m.SetValue([]byte{1, 2, 3})
	}

	return m
}

func GenerateContainerIDs(empty bool) []refs.ContainerID {
	var res []refs.ContainerID

	if !empty {
		res = append(res,
			*GenerateContainerID(false),
			*GenerateContainerID(false),
		)
	}

	return res
}

func GenerateSignature(empty bool) *refs.Signature {
	m := new(refs.Signature)

	if !empty {
		m.SetKey([]byte{1})
		m.SetSign([]byte{2})
		m.SetScheme(refs.SignatureScheme(rand.Int31() % 3))
	}

	return m
}

func GenerateChecksum(empty bool) *refs.Checksum {
	m := new(refs.Checksum)

	if !empty {
		m.SetType(1)
		m.SetSum([]byte{1, 2, 3})
	}

	return m
}

func GenerateSubnetID(empty bool) *refs.SubnetID {
	m := new(refs.SubnetID)

	if !empty {
		m.SetValue(666)
	}

	return m
}
