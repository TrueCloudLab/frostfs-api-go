package session

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/status"
	statusgrpc "github.com/TrueCloudLab/frostfs-api-go/v2/status/grpc"
)

// LocalizeFailStatus checks if passed global status.Code is related to session failure and:
//
//	then localizes the code and returns true,
//	else leaves the code unchanged and returns false.
//
// Arg must not be nil.
func LocalizeFailStatus(c *status.Code) bool {
	return status.LocalizeIfInSection(c, uint32(statusgrpc.Section_SECTION_SESSION))
}

// GlobalizeFail globalizes local code of session failure.
//
// Arg must not be nil.
func GlobalizeFail(c *status.Code) {
	c.GlobalizeSection(uint32(statusgrpc.Section_SECTION_SESSION))
}

const (
	// StatusTokenNotFound is a local status.Code value for
	// TOKEN_NOT_FOUND session failure.
	StatusTokenNotFound status.Code = iota
	// StatusTokenExpired is a local status.Code value for
	// TOKEN_EXPIRED session failure.
	StatusTokenExpired
)
