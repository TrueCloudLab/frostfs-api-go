package status

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	status "github.com/TrueCloudLab/frostfs-api-go/v2/status/grpc"
	protoutil "github.com/TrueCloudLab/frostfs-api-go/v2/util/proto"
)

const (
	_ = iota
	detailIDFNum
	detailValueFNum
)

func (x *Detail) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.UInt32Marshal(detailIDFNum, buf[offset:], x.id)
	protoutil.BytesMarshal(detailValueFNum, buf[offset:], x.val)

	return buf
}

func (x *Detail) StableSize() (size int) {
	size += protoutil.UInt32Size(detailIDFNum, x.id)
	size += protoutil.BytesSize(detailValueFNum, x.val)

	return size
}

func (x *Detail) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(status.Status_Detail))
}

const (
	_ = iota
	statusCodeFNum
	statusMsgFNum
	statusDetailsFNum
)

func (x *Status) StableMarshal(buf []byte) []byte {
	if x == nil {
		return []byte{}
	}

	if buf == nil {
		buf = make([]byte, x.StableSize())
	}

	var offset int

	offset += protoutil.UInt32Marshal(statusCodeFNum, buf[offset:], CodeToGRPC(x.code))
	offset += protoutil.StringMarshal(statusMsgFNum, buf[offset:], x.msg)

	for i := range x.details {
		offset += protoutil.NestedStructureMarshal(statusDetailsFNum, buf[offset:], &x.details[i])
	}

	return buf
}

func (x *Status) StableSize() (size int) {
	size += protoutil.UInt32Size(statusCodeFNum, CodeToGRPC(x.code))
	size += protoutil.StringSize(statusMsgFNum, x.msg)

	for i := range x.details {
		size += protoutil.NestedStructureSize(statusDetailsFNum, &x.details[i])
	}

	return size
}

func (x *Status) Unmarshal(data []byte) error {
	return message.Unmarshal(x, data, new(status.Status))
}
