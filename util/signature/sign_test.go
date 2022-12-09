package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/stretchr/testify/require"
)

type testData struct {
	data []byte
	sig  *refs.Signature
}

func (t testData) SignedDataSize() int { return len(t.data) }
func (t testData) ReadSignedData(data []byte) ([]byte, error) {
	n := copy(data, t.data)
	return data[:n], nil
}
func (t testData) GetSignature() *refs.Signature   { return t.sig }
func (t *testData) SetSignature(s *refs.Signature) { t.sig = s }

func TestWalletConnect(t *testing.T) {
	testCases := [...][]byte{
		{},
		{0},
		{1, 2},
		{3, 4, 5},
		{6, 7, 8, 9, 10, 11, 12},
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range testCases {
		td := &testData{data: tc}
		require.NoError(t, SignData(pk, td, SignWithWalletConnect()))
		require.Equal(t, refs.ECDSA_RFC6979_SHA256_WALLET_CONNECT, td.sig.GetScheme())
		require.NoError(t, VerifyData(td))
	}
}
