package message

import (
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
)

// Message represents raw Protobuf message
// that can be transmitted via several
// transport protocols.
type Message interface {
	// Must return gRPC message that can
	// be used for gRPC protocol transmission.
	ToGRPCMessage() grpc.Message

	// Must restore the message from related
	// gRPC message.
	//
	// If gRPC message is not a related one,
	// ErrUnexpectedMessageType can be returned
	// to indicate this.
	FromGRPCMessage(grpc.Message) error
}

// ErrUnexpectedMessageType is an error that
// is used to indicate message mismatch.
type ErrUnexpectedMessageType struct {
	exp, act interface{}
}

// NewUnexpectedMessageType initializes an error about message mismatch
// between act and exp.
func NewUnexpectedMessageType(act, exp interface{}) ErrUnexpectedMessageType {
	return ErrUnexpectedMessageType{
		exp: exp,
		act: act,
	}
}

func (e ErrUnexpectedMessageType) Error() string {
	return fmt.Sprintf("unexpected message type %T: expected %T", e.act, e.exp)
}
