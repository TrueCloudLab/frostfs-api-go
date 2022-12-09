package object_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/object"
	"github.com/TrueCloudLab/frostfs-api-go/v2/status"
	statustest "github.com/TrueCloudLab/frostfs-api-go/v2/status/test"
	"github.com/stretchr/testify/require"
)

func TestStatusCodes(t *testing.T) {
	statustest.TestCodes(t, object.LocalizeFailStatus, object.GlobalizeFail,
		object.StatusAccessDenied, 2048,
		object.StatusNotFound, 2049,
		object.StatusLocked, 2050,
		object.StatusLockNonRegularObject, 2051,
		object.StatusAlreadyRemoved, 2052,
		object.StatusOutOfRange, 2053,
	)
}

func TestAccessDeniedDesc(t *testing.T) {
	var st status.Status

	require.Empty(t, object.ReadAccessDeniedDesc(st))

	const desc = "some description"

	object.WriteAccessDeniedDesc(&st, desc)
	require.Equal(t, desc, object.ReadAccessDeniedDesc(st))

	object.WriteAccessDeniedDesc(&st, desc+"1")
	require.Equal(t, desc+"1", object.ReadAccessDeniedDesc(st))
}
