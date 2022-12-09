package refs_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/stretchr/testify/require"
)

func TestZeroSubnet(t *testing.T) {
	id := new(refs.SubnetID)

	require.True(t, refs.IsZeroSubnet(id))

	id.SetValue(1)
	require.False(t, refs.IsZeroSubnet(id))

	refs.MakeZeroSubnet(id)
	require.True(t, refs.IsZeroSubnet(id))
}

func TestSubnetID_MarshalText(t *testing.T) {
	var id refs.SubnetID

	const val = 15

	id.SetValue(val)

	txt, err := id.MarshalText()
	require.NoError(t, err)

	res, err := strconv.ParseUint(string(txt), 10, 32)
	require.NoError(t, err)

	require.EqualValues(t, val, res)

	t.Run("nil", func(t *testing.T) {
		var id *refs.SubnetID

		txt, err := id.MarshalText()
		require.NoError(t, err)

		res, err := strconv.ParseUint(string(txt), 10, 32)
		require.NoError(t, err)

		require.Zero(t, res)
	})
}

func TestSubnetID_UnmarshalText(t *testing.T) {
	const val = 15

	str := strconv.FormatUint(val, 10)

	var id refs.SubnetID

	err := id.UnmarshalText([]byte(str))
	require.NoError(t, err)

	require.EqualValues(t, val, id.GetValue())

	t.Run("uint32 overflow", func(t *testing.T) {
		txt := strconv.FormatUint(math.MaxUint32+1, 10)

		var id refs.SubnetID

		err := id.UnmarshalText([]byte(txt))
		require.ErrorIs(t, err, strconv.ErrRange)
	})
}
