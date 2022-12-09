package accounting

import (
	accounting "github.com/TrueCloudLab/frostfs-api-go/v2/accounting/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	refsGRPC "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (b *BalanceRequestBody) ToGRPCMessage() grpc.Message {
	var m *accounting.BalanceRequest_Body

	if b != nil {
		m = new(accounting.BalanceRequest_Body)

		m.SetOwnerId(b.ownerID.ToGRPCMessage().(*refsGRPC.OwnerID))
	}

	return m
}

func (b *BalanceRequestBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*accounting.BalanceRequest_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	ownerID := v.GetOwnerId()
	if ownerID == nil {
		b.ownerID = nil
	} else {
		if b.ownerID == nil {
			b.ownerID = new(refs.OwnerID)
		}

		err = b.ownerID.FromGRPCMessage(ownerID)
	}

	return err
}

func (b *BalanceRequest) ToGRPCMessage() grpc.Message {
	var m *accounting.BalanceRequest

	if b != nil {
		m = new(accounting.BalanceRequest)

		m.SetBody(b.body.ToGRPCMessage().(*accounting.BalanceRequest_Body))
		b.RequestHeaders.ToMessage(m)
	}

	return m
}

func (b *BalanceRequest) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*accounting.BalanceRequest)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		b.body = nil
	} else {
		if b.body == nil {
			b.body = new(BalanceRequestBody)
		}

		err = b.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return b.RequestHeaders.FromMessage(v)
}

func (d *Decimal) ToGRPCMessage() grpc.Message {
	var m *accounting.Decimal

	if d != nil {
		m = new(accounting.Decimal)

		m.SetValue(d.val)
		m.SetPrecision(d.prec)
	}

	return m
}

func (d *Decimal) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*accounting.Decimal)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	d.val = v.GetValue()
	d.prec = v.GetPrecision()

	return nil
}

func (br *BalanceResponseBody) ToGRPCMessage() grpc.Message {
	var m *accounting.BalanceResponse_Body

	if br != nil {
		m = new(accounting.BalanceResponse_Body)

		m.SetBalance(br.bal.ToGRPCMessage().(*accounting.Decimal))
	}

	return m
}

func (br *BalanceResponseBody) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*accounting.BalanceResponse_Body)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	bal := v.GetBalance()
	if bal == nil {
		br.bal = nil
	} else {
		if br.bal == nil {
			br.bal = new(Decimal)
		}

		err = br.bal.FromGRPCMessage(bal)
	}

	return err
}

func (br *BalanceResponse) ToGRPCMessage() grpc.Message {
	var m *accounting.BalanceResponse

	if br != nil {
		m = new(accounting.BalanceResponse)

		m.SetBody(br.body.ToGRPCMessage().(*accounting.BalanceResponse_Body))
		br.ResponseHeaders.ToMessage(m)
	}

	return m
}

func (br *BalanceResponse) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*accounting.BalanceResponse)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var err error

	body := v.GetBody()
	if body == nil {
		br.body = nil
	} else {
		if br.body == nil {
			br.body = new(BalanceResponseBody)
		}

		err = br.body.FromGRPCMessage(body)
		if err != nil {
			return err
		}
	}

	return br.ResponseHeaders.FromMessage(v)
}
