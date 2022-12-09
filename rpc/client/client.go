package client

import (
	"sync"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/grpc"
)

// Client represents client for exchanging messages
// with a remote server using Protobuf RPC.
type Client struct {
	*cfg

	gRPCClientOnce sync.Once
	gRPCClient     *grpc.Client
}

// New creates, configures via options and returns new Client instance.
func New(opts ...Option) *Client {
	c := defaultCfg()

	for _, opt := range opts {
		opt(c)
	}

	return &Client{
		cfg: c,
	}
}
