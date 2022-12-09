package container

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/status"
	statusgrpc "github.com/TrueCloudLab/frostfs-api-go/v2/status/grpc"
)

// LocalizeFailStatus checks if passed global status.Code is related to container failure and:
//
//	then localizes the code and returns true,
//	else leaves the code unchanged and returns false.
//
// Arg must not be nil.
func LocalizeFailStatus(c *status.Code) bool {
	return status.LocalizeIfInSection(c, uint32(statusgrpc.Section_SECTION_CONTAINER))
}

// GlobalizeFail globalizes local code of container failure.
//
// Arg must not be nil.
func GlobalizeFail(c *status.Code) {
	c.GlobalizeSection(uint32(statusgrpc.Section_SECTION_CONTAINER))
}

const (
	// StatusNotFound is a local status.Code value for
	// CONTAINER_NOT_FOUND container failure.
	StatusNotFound status.Code = iota

	// StatusEACLNotFound is a local status.Code value for
	// EACL_NOT_FOUND failure.
	StatusEACLNotFound
)
