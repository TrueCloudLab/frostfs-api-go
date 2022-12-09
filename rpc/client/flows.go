package client

import (
	"errors"
	"io"
	"sync"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/common"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

// SendUnary initializes communication session by RPC info, performs unary RPC
// and closes the session.
func SendUnary(cli *Client, info common.CallMethodInfo, req, resp message.Message, opts ...CallOption) error {
	rw, err := cli.Init(info, opts...)
	if err != nil {
		return err
	}

	err = rw.WriteMessage(req)
	if err != nil {
		return err
	}

	err = rw.ReadMessage(resp)
	if err != nil {
		return err
	}

	return rw.Close()
}

// MessageWriterCloser wraps MessageWriter
// and io.Closer interfaces.
type MessageWriterCloser interface {
	MessageWriter
	io.Closer
}

type clientStreamWriterCloser struct {
	MessageReadWriter

	resp message.Message
}

func (c *clientStreamWriterCloser) Close() error {
	err := c.MessageReadWriter.Close()
	if err != nil {
		return err
	}

	return c.ReadMessage(c.resp)
}

// OpenClientStream initializes communication session by RPC info, opens client-side stream
// and returns its interface.
//
// All stream writes must be performed before the closing. Close must be called once.
func OpenClientStream(cli *Client, info common.CallMethodInfo, resp message.Message, opts ...CallOption) (MessageWriterCloser, error) {
	rw, err := cli.Init(info, opts...)
	if err != nil {
		return nil, err
	}

	return &clientStreamWriterCloser{
		MessageReadWriter: rw,
		resp:              resp,
	}, nil
}

// MessageReaderCloser wraps MessageReader
// and io.Closer interface.
type MessageReaderCloser interface {
	MessageReader
	io.Closer
}

type serverStreamReaderCloser struct {
	rw MessageReadWriter

	once sync.Once

	req message.Message
}

func (s *serverStreamReaderCloser) ReadMessage(msg message.Message) error {
	var err error

	s.once.Do(func() {
		err = s.rw.WriteMessage(s.req)
	})

	if err != nil {
		return err
	}

	err = s.rw.ReadMessage(msg)
	if !errors.Is(err, io.EOF) {
		return err
	}

	err = s.rw.Close()
	if err != nil {
		return err
	}

	return io.EOF
}

// OpenServerStream initializes communication session by RPC info, opens server-side stream
// and returns its interface.
//
// All stream reads must be performed before the closing. Close must be called once.
func OpenServerStream(cli *Client, info common.CallMethodInfo, req message.Message, opts ...CallOption) (MessageReader, error) {
	rw, err := cli.Init(info, opts...)
	if err != nil {
		return nil, err
	}

	return &serverStreamReaderCloser{
		rw:  rw,
		req: req,
	}, nil
}
