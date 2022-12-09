package common_test

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
	"github.com/stretchr/testify/require"
)

const (
	testServiceName = "test service"
	testRPCName     = "test RPC"
)

func TestCallMethodInfoUnary(t *testing.T) {
	i := common.CallMethodInfoUnary(testServiceName, testRPCName)

	require.Equal(t, testServiceName, i.Service)
	require.Equal(t, testRPCName, i.Name)
	require.False(t, i.ClientStream())
	require.False(t, i.ServerStream())
}

func TestCallMethodInfoServerStream(t *testing.T) {
	i := common.CallMethodInfoServerStream(testServiceName, testRPCName)

	require.Equal(t, testServiceName, i.Service)
	require.Equal(t, testRPCName, i.Name)
	require.False(t, i.ClientStream())
	require.True(t, i.ServerStream())
}

func TestCallMethodInfoClientStream(t *testing.T) {
	i := common.CallMethodInfoClientStream(testServiceName, testRPCName)

	require.Equal(t, testServiceName, i.Service)
	require.Equal(t, testRPCName, i.Name)
	require.True(t, i.ClientStream())
	require.False(t, i.ServerStream())
}

func TestCallMethodInfoBidirectionalStream(t *testing.T) {
	i := common.CallMethodInfoBidirectionalStream(testServiceName, testRPCName)

	require.Equal(t, testServiceName, i.Service)
	require.Equal(t, testRPCName, i.Name)
	require.True(t, i.ClientStream())
	require.True(t, i.ServerStream())
}
