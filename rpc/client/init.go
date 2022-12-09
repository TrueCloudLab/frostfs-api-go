package client

import (
	"io"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
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

	return c.initGRPC(info, prm)
}

type rwGRPC struct {
	grpc.MessageReadWriter
}

func (g rwGRPC) ReadMessage(m message.Message) error {
	// Can be optimized: we can create blank message here.
	gm := m.ToGRPCMessage()

	if err := g.MessageReadWriter.ReadMessage(gm); err != nil {
		return err
	}

	return m.FromGRPCMessage(gm)
}

func (g rwGRPC) WriteMessage(m message.Message) error {
	return g.MessageReadWriter.WriteMessage(m.ToGRPCMessage())
}

func (c *Client) initGRPC(info common.CallMethodInfo, prm *callParameters) (MessageReadWriter, error) {
	if err := c.createGRPCClient(prm.ctx); err != nil {
		return nil, err
	}

	rw, err := c.gRPCClient.Init(info, grpc.WithContext(prm.ctx))
	if err != nil {
		return nil, err
	}

	return &rwGRPC{
		MessageReadWriter: rw,
	}, nil
}
