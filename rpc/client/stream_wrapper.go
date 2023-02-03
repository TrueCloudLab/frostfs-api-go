package client

import (
	"context"
	"time"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	"google.golang.org/grpc"
)

type streamWrapper struct {
	grpc.ClientStream
	timeout time.Duration
	cancel  context.CancelFunc
}

func (w streamWrapper) ReadMessage(m message.Message) error {
	// Can be optimized: we can create blank message here.
	gm := m.ToGRPCMessage()

	err := w.withTimeout(func() error {
		return w.ClientStream.RecvMsg(gm)
	})
	if err != nil {
		return err
	}

	return m.FromGRPCMessage(gm)
}

func (w streamWrapper) WriteMessage(m message.Message) error {
	return w.withTimeout(func() error {
		return w.ClientStream.SendMsg(m.ToGRPCMessage())
	})
}

func (w *streamWrapper) Close() error {
	return w.withTimeout(w.ClientStream.CloseSend)
}

func (w *streamWrapper) withTimeout(closure func() error) error {
	ch := make(chan error, 1)
	go func() {
		ch <- closure()
		close(ch)
	}()

	tt := time.NewTimer(w.timeout)

	select {
	case err := <-ch:
		tt.Stop()
		return err
	case <-tt.C:
		w.cancel()
		return context.DeadlineExceeded
	}
}
