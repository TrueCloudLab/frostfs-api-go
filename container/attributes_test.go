package container_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/container"
	containertest "github.com/TrueCloudLab/frostfs-api-go/v2/container/test"
	"github.com/stretchr/testify/require"
)

func TestContainer_HomomorphicHashingDisabled(t *testing.T) {
	cnr := containertest.GenerateContainer(false)

	t.Run("defaults", func(t *testing.T) {
		require.True(t, cnr.HomomorphicHashingState())
	})

	t.Run("disabled", func(t *testing.T) {
		attr := container.Attribute{}
		attr.SetKey(container.SysAttributeHomomorphicHashing)
		attr.SetValue("NOT_true")

		cnr.SetAttributes(append(cnr.GetAttributes(), attr))
		require.True(t, cnr.HomomorphicHashingState())

		attr.SetValue("true")

		cnr.SetAttributes([]container.Attribute{attr})
		require.False(t, cnr.HomomorphicHashingState())
	})
}

func TestContainer_SetHomomorphicHashingState(t *testing.T) {
	cnr := containertest.GenerateContainer(false)
	attrs := cnr.GetAttributes()
	attrLen := len(attrs)

	cnr.SetHomomorphicHashingState(true)

	// enabling hashing should not add any new attributes
	require.Equal(t, attrLen, len(cnr.GetAttributes()))
	require.True(t, cnr.HomomorphicHashingState())

	cnr.SetHomomorphicHashingState(false)

	// disabling hashing should add exactly one attribute
	require.Equal(t, attrLen+1, len(cnr.GetAttributes()))
	require.False(t, cnr.HomomorphicHashingState())

	cnr.SetHomomorphicHashingState(true)

	// enabling hashing should remove 1 attribute if
	// hashing was disabled before
	require.Equal(t, attrLen, len(cnr.GetAttributes()))
	require.True(t, cnr.HomomorphicHashingState())

	// hashing operations should not change any other attributes
	require.ElementsMatch(t, attrs, cnr.GetAttributes())
}
