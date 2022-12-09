package object_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/object"
	objecttest "github.com/TrueCloudLab/frostfs-api-go/v2/object/test"
	"github.com/stretchr/testify/require"
)

func TestLockRW(t *testing.T) {
	var l object.Lock
	var obj object.Object

	require.Error(t, object.ReadLock(&l, obj))

	l = *objecttest.GenerateLock(false)

	object.WriteLock(&obj, l)

	var l2 object.Lock

	require.NoError(t, object.ReadLock(&l2, obj))

	require.Equal(t, l, l2)
}
