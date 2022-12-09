package accounting

import (
	accounting "github.com/TrueCloudLab/frostfs-api-go/v2/accounting/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	protoutil "github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	decimalValueField     = 1
	decimalPrecisionField = 2

	balanceReqBodyOwnerField = 1

	balanceRespBodyDecimalField = 1
)

func (d *Decimal) StableMarshal(buf []byte) []byte {
	if d == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, d.StableSize())
	}

	var offset int

	offset += protoutil.Int64Marshal(decimalValueField, buf[offset:], d.val)
	protoutil.UInt32Marshal(decimalPrecisionField, buf[offset:], d.prec)

	return buf
}

func (d *Decimal) StableSize() (size int) {
	if d == nil {
		return 0
	}

	size += protoutil.Int64Size(decimalValueField, d.val)
	size += protoutil.UInt32Size(decimalPrecisionField, d.prec)

	return size
}

func (d *Decimal) Unmarshal(data []byte) error {
	return message.Unmarshal(d, data, new(accounting.Decimal))
}

func (b *BalanceRequestBody) StableMarshal(buf []byte) []byte {
	if b == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, b.StableSize())
	}

	protoutil.NestedStructureMarshal(balanceReqBodyOwnerField, buf, b.ownerID)

	return buf
}

func (b *BalanceRequestBody) StableSize() (size int) {
	if b == nil {
		return 0
	}

	size = protoutil.NestedStructureSize(balanceReqBodyOwnerField, b.ownerID)

	return size
}

func (b *BalanceRequestBody) Unmarshal(data []byte) error {
	return message.Unmarshal(b, data, new(accounting.BalanceRequest_Body))
}

func (br *BalanceResponseBody) StableMarshal(buf []byte) []byte {
	if br == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, br.StableSize())
	}

	protoutil.NestedStructureMarshal(balanceRespBodyDecimalField, buf, br.bal)

	return buf
}

func (br *BalanceResponseBody) StableSize() (size int) {
	if br == nil {
		return 0
	}

	size = protoutil.NestedStructureSize(balanceRespBodyDecimalField, br.bal)

	return size
}

func (br *BalanceResponseBody) Unmarshal(data []byte) error {
	return message.Unmarshal(br, data, new(accounting.BalanceResponse_Body))
}
