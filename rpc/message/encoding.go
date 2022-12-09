package message

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// GRPCConvertedMessage is an interface
// of the gRPC message that is used
// for Message encoding/decoding.
type GRPCConvertedMessage interface {
	grpc.Message
	proto.Message
}

// Unmarshal decodes m from its Protobuf binary representation
// via related gRPC message.
//
// gm should be tof the same type as the m.ToGRPCMessage() return.
func Unmarshal(m Message, data []byte, gm GRPCConvertedMessage) error {
	if err := proto.Unmarshal(data, gm); err != nil {
		return err
	}

	return m.FromGRPCMessage(gm)
}

// MarshalJSON encodes m to Protobuf JSON representation.
func MarshalJSON(m Message) ([]byte, error) {
	return protojson.MarshalOptions{
		EmitUnpopulated: true,
	}.Marshal(
		m.ToGRPCMessage().(proto.Message),
	)
}

// UnmarshalJSON decodes m from its Protobuf JSON representation
// via related gRPC message.
//
// gm should be tof the same type as the m.ToGRPCMessage() return.
func UnmarshalJSON(m Message, data []byte, gm GRPCConvertedMessage) error {
	if err := protojson.Unmarshal(data, gm); err != nil {
		return err
	}

	return m.FromGRPCMessage(gm)
}
