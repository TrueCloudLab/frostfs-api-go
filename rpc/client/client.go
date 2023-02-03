package client

// Client represents client for exchanging messages
// with a remote server using Protobuf RPC.
type Client struct {
	cfg
}

// New creates, configures via options and returns new Client instance.
func New(opts ...Option) *Client {
	var c Client
	c.initDefault()

	for _, opt := range opts {
		opt(&c.cfg)
	}

	return &c
}
