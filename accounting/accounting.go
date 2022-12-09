package accounting

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
)

type BalanceRequestBody struct {
	ownerID *refs.OwnerID
}

type BalanceResponseBody struct {
	bal *Decimal
}

type Decimal struct {
	val int64

	prec uint32
}

type BalanceRequest struct {
	body *BalanceRequestBody

	session.RequestHeaders
}

type BalanceResponse struct {
	body *BalanceResponseBody

	session.ResponseHeaders
}

func (b *BalanceRequestBody) GetOwnerID() *refs.OwnerID {
	if b != nil {
		return b.ownerID
	}

	return nil
}

func (b *BalanceRequestBody) SetOwnerID(v *refs.OwnerID) {
	b.ownerID = v
}

func (b *BalanceRequest) GetBody() *BalanceRequestBody {
	if b != nil {
		return b.body
	}

	return nil
}

func (b *BalanceRequest) SetBody(v *BalanceRequestBody) {
	b.body = v
}

func (d *Decimal) GetValue() int64 {
	if d != nil {
		return d.val
	}

	return 0
}

func (d *Decimal) SetValue(v int64) {
	d.val = v
}

func (d *Decimal) GetPrecision() uint32 {
	if d != nil {
		return d.prec
	}

	return 0
}

func (d *Decimal) SetPrecision(v uint32) {
	d.prec = v
}

func (br *BalanceResponseBody) GetBalance() *Decimal {
	if br != nil {
		return br.bal
	}

	return nil
}

func (br *BalanceResponseBody) SetBalance(v *Decimal) {
	br.bal = v
}

func (br *BalanceResponse) GetBody() *BalanceResponseBody {
	if br != nil {
		return br.body
	}

	return nil
}

func (br *BalanceResponse) SetBody(v *BalanceResponseBody) {
	br.body = v
}
