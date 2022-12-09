package object

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/status"
	statusgrpc "github.com/TrueCloudLab/frostfs-api-go/v2/status/grpc"
)

// LocalizeFailStatus checks if passed global status.Code is related to object failure and:
//
//	then localizes the code and returns true,
//	else leaves the code unchanged and returns false.
//
// Arg must not be nil.
func LocalizeFailStatus(c *status.Code) bool {
	return status.LocalizeIfInSection(c, uint32(statusgrpc.Section_SECTION_OBJECT))
}

// GlobalizeFail globalizes local code of object failure.
//
// Arg must not be nil.
func GlobalizeFail(c *status.Code) {
	c.GlobalizeSection(uint32(statusgrpc.Section_SECTION_OBJECT))
}

const (
	// StatusAccessDenied is a local status.Code value for
	// ACCESS_DENIED object failure.
	StatusAccessDenied status.Code = iota
	// StatusNotFound is a local status.Code value for
	// OBJECT_NOT_FOUND object failure.
	StatusNotFound
	// StatusLocked is a local status.Code value for
	// LOCKED object failure.
	StatusLocked
	// StatusLockNonRegularObject is a local status.Code value for
	// LOCK_NON_REGULAR_OBJECT object failure.
	StatusLockNonRegularObject
	// StatusAlreadyRemoved is a local status.Code value for
	// OBJECT_ALREADY_REMOVED object failure.
	StatusAlreadyRemoved
	// StatusOutOfRange is a local status.Code value for
	// OUT_OF_RANGE object failure.
	StatusOutOfRange
)

const (
	// detailAccessDeniedDesc is a StatusAccessDenied detail ID for
	// human-readable description.
	detailAccessDeniedDesc = iota
)

// WriteAccessDeniedDesc writes human-readable description of StatusAccessDenied
// into status.Status as a detail. The status must not be nil.
//
// Existing details are expected to be ID-unique, otherwise undefined behavior.
func WriteAccessDeniedDesc(st *status.Status, desc string) {
	var found bool

	st.IterateDetails(func(d *status.Detail) bool {
		if d.ID() == detailAccessDeniedDesc {
			found = true
			d.SetValue([]byte(desc))
		}

		return found
	})

	if !found {
		var d status.Detail

		d.SetID(detailAccessDeniedDesc)
		d.SetValue([]byte(desc))

		st.AppendDetails(d)
	}
}

// ReadAccessDeniedDesc looks up for status detail with human-readable description
// of StatusAccessDenied. Returns empty string if detail is missing.
func ReadAccessDeniedDesc(st status.Status) (desc string) {
	st.IterateDetails(func(d *status.Detail) bool {
		if d.ID() == detailAccessDeniedDesc {
			desc = string(d.Value())
			return true
		}

		return false
	})

	return
}
