package signature

import (
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/accounting"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	crypto "github.com/TrueCloudLab/frostfs-crypto"
	"github.com/stretchr/testify/require"
)

func TestBalanceResponse(t *testing.T) {
	dec := new(accounting.Decimal)
	dec.SetValue(100)

	body := new(accounting.BalanceResponseBody)
	body.SetBalance(dec)

	meta := new(session.ResponseMetaHeader)
	meta.SetTTL(1)

	req := new(accounting.BalanceResponse)
	req.SetBody(body)
	req.SetMetaHeader(meta)

	// verify unsigned request
	require.Error(t, VerifyServiceMessage(req))

	key, err := crypto.LoadPrivateKey("Kwk6k2eC3L3QuPvD8aiaNyoSXgQ2YL1bwS5CP1oKoA9waeAze97s")
	require.NoError(t, err)

	// sign request
	require.NoError(t, SignServiceMessage(key, req))

	// verification must pass
	require.NoError(t, VerifyServiceMessage(req))

	// add level to meta header matryoshka
	meta = new(session.ResponseMetaHeader)
	meta.SetOrigin(req.GetMetaHeader())
	req.SetMetaHeader(meta)

	// sign request
	require.NoError(t, SignServiceMessage(key, req))

	// verification must pass
	require.NoError(t, VerifyServiceMessage(req))

	// corrupt body
	dec.SetValue(dec.GetValue() + 1)

	// verification must fail
	require.Error(t, VerifyServiceMessage(req))

	// restore body
	dec.SetValue(dec.GetValue() - 1)

	// corrupt meta header
	meta.SetTTL(meta.GetTTL() + 1)

	// verification must fail
	require.Error(t, VerifyServiceMessage(req))

	// restore meta header
	meta.SetTTL(meta.GetTTL() - 1)

	// corrupt origin verification header
	req.GetVerificationHeader().SetOrigin(nil)

	// verification must fail
	require.Error(t, VerifyServiceMessage(req))
}

func BenchmarkSignRequest(b *testing.B) {
	key, _ := crypto.LoadPrivateKey("Kwk6k2eC3L3QuPvD8aiaNyoSXgQ2YL1bwS5CP1oKoA9waeAze97s")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dec := new(accounting.Decimal)
		dec.SetValue(100)

		body := new(accounting.BalanceResponseBody)
		body.SetBalance(dec)

		meta := new(session.ResponseMetaHeader)
		meta.SetTTL(1)

		resp := new(accounting.BalanceResponse)
		resp.SetBody(body)
		resp.SetMetaHeader(meta)

		b.StartTimer()
		SignServiceMessage(key, resp)
	}
}

func BenchmarkVerifyRequest(b *testing.B) {
	key, _ := crypto.LoadPrivateKey("Kwk6k2eC3L3QuPvD8aiaNyoSXgQ2YL1bwS5CP1oKoA9waeAze97s")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dec := new(accounting.Decimal)
		dec.SetValue(100)

		body := new(accounting.BalanceResponseBody)
		body.SetBalance(dec)

		meta := new(session.ResponseMetaHeader)
		meta.SetTTL(1)

		resp := new(accounting.BalanceResponse)
		resp.SetBody(body)
		resp.SetMetaHeader(meta)
		SignServiceMessage(key, resp)
		b.StartTimer()

		VerifyServiceMessage(resp)
	}
}
