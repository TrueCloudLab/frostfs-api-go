package netmap_test

import (
	"strconv"
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/netmap"
	netmaptest "github.com/TrueCloudLab/frostfs-api-go/v2/netmap/test"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/stretchr/testify/require"
)

func subnetAttrKey(val string) string {
	return "__NEOFS__SUBNET_" + val
}

func assertSubnetAttrKey(t *testing.T, attr *netmap.Attribute, num uint32) {
	require.Equal(t, subnetAttrKey(strconv.FormatUint(uint64(num), 10)), attr.GetKey())
}

func BenchmarkNodeAttributes(b *testing.B) {
	const size = 50

	id := new(refs.SubnetID)
	id.SetValue(12)

	attrs := make([]netmap.Attribute, size)
	for i := range attrs {
		if i == size/2 {
			attrs[i] = *netmaptest.GenerateAttribute(false)
		} else {
			data, err := id.MarshalText()
			require.NoError(b, err)

			attrs[i].SetKey(subnetAttrKey(string(data)))
			attrs[i].SetValue("True")
		}
	}

	var info netmap.NodeSubnetInfo
	info.SetID(id)
	info.SetEntryFlag(false)

	node := new(netmap.NodeInfo)

	// When using a single slice `StartTimer` overhead is comparable to the
	// function execution time, so we reduce this cost by updating slices in groups.
	const cacheSize = 1000
	a := make([][]netmap.Attribute, cacheSize)
	for i := range a {
		a[i] = make([]netmap.Attribute, size)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if i%cacheSize == 0 {
			b.StopTimer()
			for j := range a {
				copy(a[j], attrs)
			}
			b.StartTimer()
		}
		node.SetAttributes(a[i%cacheSize])
		netmap.WriteSubnetInfo(node, info)
		if len(node.GetAttributes())+1 != len(attrs) {
			b.FailNow()
		}
	}
}

func TestWriteSubnetInfo(t *testing.T) {
	t.Run("entry", func(t *testing.T) {
		t.Run("zero subnet", func(t *testing.T) {
			var (
				node netmap.NodeInfo
				info netmap.NodeSubnetInfo
			)

			netmap.WriteSubnetInfo(&node, info)

			// entry to zero subnet does not require an attribute
			attrs := node.GetAttributes()
			require.Empty(t, attrs)

			// exit the subnet
			info.SetEntryFlag(false)

			netmap.WriteSubnetInfo(&node, info)

			// exit from zero subnet should be clearly reflected in attributes
			attrs = node.GetAttributes()
			require.Len(t, attrs, 1)

			attr := &attrs[0]
			assertSubnetAttrKey(t, attr, 0)
			require.Equal(t, "False", attr.GetValue())

			// again enter to zero subnet
			info.SetEntryFlag(true)

			netmap.WriteSubnetInfo(&node, info)

			// attribute should be removed
			attrs = node.GetAttributes()
			require.Empty(t, attrs)
		})

		t.Run("non-zero subnet", func(t *testing.T) {
			var (
				node netmap.NodeInfo
				info netmap.NodeSubnetInfo
				id   refs.SubnetID
			)

			// create non-zero subnet ID
			const num = 15

			id.SetValue(num)

			// enter to the subnet
			info.SetID(&id)
			info.SetEntryFlag(true)

			netmap.WriteSubnetInfo(&node, info)

			// check attribute format
			attrs := node.GetAttributes()
			require.Len(t, attrs, 1)

			attr := &attrs[0]
			assertSubnetAttrKey(t, attr, num)
			require.Equal(t, "True", attr.GetValue())

			// again exit the subnet
			info.SetEntryFlag(false)

			netmap.WriteSubnetInfo(&node, info)

			// attribute should be removed
			attrs = node.GetAttributes()
			require.Empty(t, attrs)
		})
	})
}

func TestSubnets(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var node netmap.NodeInfo

		called := 0

		err := netmap.IterateSubnets(&node, func(id refs.SubnetID) error {
			called++

			require.True(t, refs.IsZeroSubnet(&id))

			return nil
		})

		require.NoError(t, err)
		require.EqualValues(t, 1, called)
	})

	t.Run("with correct attribute", func(t *testing.T) {
		var (
			node netmap.NodeInfo

			attrEntry, attrExit netmap.Attribute
		)

		const (
			numEntry = 13
			numExit  = 14
		)

		attrEntry.SetKey(subnetAttrKey(strconv.FormatUint(numEntry, 10)))
		attrEntry.SetValue("True")

		attrExit.SetKey(subnetAttrKey(strconv.FormatUint(numExit, 10)))
		attrExit.SetValue("False")

		attrs := []netmap.Attribute{attrEntry, attrEntry}

		node.SetAttributes(attrs)

		mCalledNums := make(map[uint32]struct{})

		err := netmap.IterateSubnets(&node, func(id refs.SubnetID) error {
			mCalledNums[id.GetValue()] = struct{}{}

			return nil
		})

		require.NoError(t, err)
		require.Len(t, mCalledNums, 2)

		_, ok := mCalledNums[numEntry]
		require.True(t, ok)

		_, ok = mCalledNums[numExit]
		require.False(t, ok)

		_, ok = mCalledNums[0]
		require.True(t, ok)
	})

	t.Run("with incorrect attribute", func(t *testing.T) {
		assertErr := func(attr netmap.Attribute) {
			var node netmap.NodeInfo

			node.SetAttributes([]netmap.Attribute{attr})

			require.Error(t, netmap.IterateSubnets(&node, func(refs.SubnetID) error {
				return nil
			}))
		}

		t.Run("incorrect key", func(t *testing.T) {
			var attr netmap.Attribute

			attr.SetKey(subnetAttrKey("one-two-three"))

			assertErr(attr)
		})

		t.Run("incorrect value", func(t *testing.T) {
			var attr netmap.Attribute

			attr.SetKey(subnetAttrKey("1"))

			for _, invalidVal := range []string{
				"",
				"Troo",
				"Fols",
			} {
				attr.SetValue(invalidVal)
				assertErr(attr)
			}

			assertErr(attr)
		})
	})

	t.Run("remove entry", func(t *testing.T) {
		t.Run("zero", func(t *testing.T) {
			var node netmap.NodeInfo

			// enter to some non-zero subnet so that zero is not the only one
			var attr netmap.Attribute

			attr.SetKey(subnetAttrKey("321"))
			attr.SetValue("True")

			attrs := []netmap.Attribute{attr}
			node.SetAttributes(attrs)

			err := netmap.IterateSubnets(&node, func(id refs.SubnetID) error {
				if refs.IsZeroSubnet(&id) {
					return netmap.ErrRemoveSubnet
				}

				return nil
			})

			require.NoError(t, err)

			attrs = node.GetAttributes()
			require.Len(t, attrs, 2)

			found := false

			for i := range attrs {
				if attrs[i].GetKey() == subnetAttrKey("0") {
					require.Equal(t, "False", attrs[i].GetValue())
					found = true
				}
			}

			require.True(t, found)
		})

		t.Run("non-zero", func(t *testing.T) {
			var (
				node netmap.NodeInfo
				attr netmap.Attribute
			)

			attr.SetKey(subnetAttrKey("99"))
			attr.SetValue("True")

			attrs := []netmap.Attribute{attr}
			node.SetAttributes(attrs)

			err := netmap.IterateSubnets(&node, func(id refs.SubnetID) error {
				if !refs.IsZeroSubnet(&id) {
					return netmap.ErrRemoveSubnet
				}

				return nil
			})

			require.NoError(t, err)

			attrs = node.GetAttributes()
			require.Empty(t, attrs)
		})

		t.Run("all", func(t *testing.T) {
			var (
				node  netmap.NodeInfo
				attrs []netmap.Attribute
			)

			// enter to some non-zero subnet so that zero is not the only one
			for i := 1; i <= 5; i++ {
				var attr netmap.Attribute

				attr.SetKey(subnetAttrKey(strconv.Itoa(i)))
				attr.SetValue("True")

				attrs = append(attrs, attr)
			}

			node.SetAttributes(attrs)

			err := netmap.IterateSubnets(&node, func(id refs.SubnetID) error {
				return netmap.ErrRemoveSubnet
			})

			require.Error(t, err)
		})
	})

	t.Run("zero subnet removal via attribute", func(t *testing.T) {
		var (
			node netmap.NodeInfo

			attrZero, attrOther netmap.Attribute
		)

		attrZero.SetKey(subnetAttrKey("0"))
		attrZero.SetValue("False")

		attrOther.SetKey(subnetAttrKey("1"))
		attrOther.SetValue("True")

		node.SetAttributes([]netmap.Attribute{attrZero, attrOther})

		calledCount := 0

		err := netmap.IterateSubnets(&node, func(id refs.SubnetID) error {
			require.False(t, refs.IsZeroSubnet(&id))
			calledCount++
			return nil
		})

		require.NoError(t, err)
		require.EqualValues(t, 1, calledCount)
	})
}
