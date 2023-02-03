package client

import (
	"crypto/tls"
	"time"

	"google.golang.org/grpc"
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

	tlsCfg *tls.Config

	conn *grpc.ClientConn
}

const (
	defaultDialTimeout = 5 * time.Second
	defaultRWTimeout   = 1 * time.Minute
)

func (c *cfg) initDefault() {
	c.dialTimeout = defaultDialTimeout
	c.rwTimeout = defaultRWTimeout
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
