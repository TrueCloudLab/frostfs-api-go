package status

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	status "github.com/TrueCloudLab/frostfs-api-go/v2/status/grpc"
)

func (x *Detail) ToGRPCMessage() grpc.Message {
	var m *status.Status_Detail

	if x != nil {
		m = new(status.Status_Detail)

		m.SetId(x.id)
		m.SetValue(x.val)
	}

	return m
}

func (x *Detail) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*status.Status_Detail)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	x.id = v.GetId()
	x.val = v.GetValue()

	return nil
}

func CodeFromGRPC(v uint32) Code {
	return Code(v)
}

func CodeToGRPC(v Code) uint32 {
	return uint32(v)
}

func (x *Status) ToGRPCMessage() grpc.Message {
	var m *status.Status

	if x != nil {
		m = new(status.Status)

		m.SetCode(CodeToGRPC(x.code))
		m.SetMessage(x.msg)

		var ds []*status.Status_Detail

		if ln := len(x.details); ln > 0 {
			ds = make([]*status.Status_Detail, 0, ln)

			for i := 0; i < ln; i++ {
				ds = append(ds, x.details[i].ToGRPCMessage().(*status.Status_Detail))
			}
		}

		m.SetDetails(ds)
	}

	return m
}

func (x *Status) FromGRPCMessage(m grpc.Message) error {
	v, ok := m.(*status.Status)
	if !ok {
		return message.NewUnexpectedMessageType(m, v)
	}

	var (
		ds   []Detail
		dsV2 = v.GetDetails()
	)

	if dsV2 != nil {
		ln := len(dsV2)

		ds = make([]Detail, ln)

		for i := 0; i < ln; i++ {
			if dsV2[i] != nil {
				if err := ds[i].FromGRPCMessage(dsV2[i]); err != nil {
					return err
				}
			}
		}
	}

	x.details = ds
	x.msg = v.GetMessage()
	x.code = CodeFromGRPC(v.GetCode())

	return nil
}
