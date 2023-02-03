package client

import (
	"context"
	"io"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	"google.golang.org/grpc"
)

// MessageReader is an interface of the Message reader.
type MessageReader interface {
	// ReadMessage reads the next Message.
	//
	// Returns io.EOF if there are no more messages to read.
	// ReadMessage should not be called after io.EOF occasion.
	ReadMessage(message.Message) error
}

// MessageWriter is an interface of the Message writer.
type MessageWriter interface {
	// WriteMessage writers the next Message.
	//
	// WriteMessage should not be called after any error.
	WriteMessage(message.Message) error
}

// MessageReadWriter is a component interface
// for transmitting raw Protobuf messages.
type MessageReadWriter interface {
	MessageReader
	MessageWriter

	// Closes the communication session.
	//
	// All calls to send/receive messages must be done before closing.
	io.Closer
}

// Init initiates a messaging session and returns the interface for message transmitting.
func (c *Client) Init(info common.CallMethodInfo, opts ...CallOption) (MessageReadWriter, error) {
	prm := defaultCallParameters()

	for _, opt := range opts {
		opt(prm)
	}

	if err := c.openGRPCConn(prm.ctx); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(prm.ctx)
	stream, err := c.conn.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    info.Name,
		ServerStreams: info.ServerStream(),
		ClientStreams: info.ClientStream(),
	}, toMethodName(info))
	if err != nil {
		cancel()
		return nil, err
	}

	return &streamWrapper{
		ClientStream: stream,
		cancel:       cancel,
		timeout:      c.rwTimeout,
	}, nil
}
