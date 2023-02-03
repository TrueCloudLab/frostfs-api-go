package client

import (
	"crypto/tls"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	grpcScheme    = "grpc"
	grpcTLSScheme = "grpcs"
)

// Option is a Client's option.
type Option func(*cfg)

type cfg struct {
	addr string

	dialTimeout time.Duration
	rwTimeout   time.Duration

	tlsCfg       *tls.Config
	grpcDialOpts []grpc.DialOption

	conn *grpc.ClientConn
}

const (
	defaultDialTimeout      = 5 * time.Second
	defaultKeepAliveTimeout = 5 * time.Second
	defaultRWTimeout        = 1 * time.Minute
)

func (c *cfg) initDefault() {
	c.dialTimeout = defaultDialTimeout
	c.rwTimeout = defaultRWTimeout
	c.grpcDialOpts = []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Timeout: defaultKeepAliveTimeout,
		}),
	}
}

// WithNetworkAddress returns option to specify
// network address of the remote server.
//
// Ignored if WithGRPCConn is provided.
func WithNetworkAddress(v string) Option {
	return func(c *cfg) {
		if v != "" {
			c.addr = v
		}
	}
}

// WithNetworkURIAddress combines WithNetworkAddress and WithTLSCfg options
// based on arguments.
//
// Do not use along with WithNetworkAddress and WithTLSCfg.
//
// Ignored if WithGRPCConn is provided.
func WithNetworkURIAddress(addr string, tlsCfg *tls.Config) []Option {
	host, isTLS, err := ParseURI(addr)
	if err != nil {
		return nil
	}

	opts := make([]Option, 2)
	opts[0] = WithNetworkAddress(host)
	if isTLS {
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		opts[1] = WithTLSCfg(tlsCfg)
	} else {
		opts[1] = WithTLSCfg(nil)
	}

	return opts
}

// WithDialTimeout returns option to specify
// dial timeout of the remote server connection.
//
// Ignored if WithGRPCConn is provided.
func WithDialTimeout(v time.Duration) Option {
	return func(c *cfg) {
		if v > 0 {
			c.dialTimeout = v
		}
	}
}

// WithRWTimeout returns option to specify timeout
// for reading and writing single gRPC message.
func WithRWTimeout(v time.Duration) Option {
	return func(c *cfg) {
		if v > 0 {
			c.rwTimeout = v
		}
	}
}

// WithTLSCfg returns option to specify
// TLS configuration.
//
// Ignored if WithGRPCConn is provided.
func WithTLSCfg(v *tls.Config) Option {
	return func(c *cfg) {
		c.tlsCfg = v
	}
}

// WithGRPCConn returns option to specify
// gRPC virtual connection.
func WithGRPCConn(v *grpc.ClientConn) Option {
	return func(c *cfg) {
		if v != nil {
			c.conn = v
		}
	}
}

// WithGRPCDialOptions returns an option to specify grpc.DialOption.
func WithGRPCDialOptions(opts []grpc.DialOption) Option {
	return func(c *cfg) {
		c.grpcDialOpts = append(c.grpcDialOpts, opts...)
	}
}
