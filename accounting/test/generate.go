package accountingtest

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/accounting"
	accountingtest "github.com/TrueCloudLab/frostfs-api-go/v2/refs/test"
	sessiontest "github.com/TrueCloudLab/frostfs-api-go/v2/session/test"
)

func GenerateBalanceRequest(empty bool) *accounting.BalanceRequest {
	m := new(accounting.BalanceRequest)

	if !empty {
		m.SetBody(GenerateBalanceRequestBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateRequestMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateRequestVerificationHeader(empty))

	return m
}

func GenerateBalanceRequestBody(empty bool) *accounting.BalanceRequestBody {
	m := new(accounting.BalanceRequestBody)

	if !empty {
		m.SetOwnerID(accountingtest.GenerateOwnerID(false))
	}

	return m
}

func GenerateBalanceResponse(empty bool) *accounting.BalanceResponse {
	m := new(accounting.BalanceResponse)

	if !empty {
		m.SetBody(GenerateBalanceResponseBody(false))
	}

	m.SetMetaHeader(sessiontest.GenerateResponseMetaHeader(empty))
	m.SetVerificationHeader(sessiontest.GenerateResponseVerificationHeader(empty))

	return m
}

func GenerateBalanceResponseBody(empty bool) *accounting.BalanceResponseBody {
	m := new(accounting.BalanceResponseBody)

	if !empty {
		m.SetBalance(GenerateDecimal(false))
	}

	return m
}

func GenerateDecimal(empty bool) *accounting.Decimal {
	m := new(accounting.Decimal)

	if !empty {
		m.SetValue(1)
		m.SetPrecision(2)
	}

	return m
}
