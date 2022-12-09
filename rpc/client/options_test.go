package client

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithNetworkURIAddress(t *testing.T) {
	hostPort := "frostfs.example.com:8080"
	apiPort := "127.0.0.1:8080"
	serverName := "testServer"

	testCases := []struct {
		uri       string
		tlsConfig *tls.Config

		wantHost string
		wantTLS  bool
	}{
		{
			uri:       grpcScheme + "://" + hostPort,
			tlsConfig: nil,
			wantHost:  "frostfs.example.com:8080",
			wantTLS:   false,
		},
		{
			uri:       grpcScheme + "://" + hostPort,
			tlsConfig: &tls.Config{},
			wantHost:  "frostfs.example.com:8080",
			wantTLS:   false,
		},
		{
			uri:       grpcTLSScheme + "://" + hostPort,
			tlsConfig: nil,
			wantHost:  "frostfs.example.com:8080",
			wantTLS:   true,
		},
		{
			uri:       grpcTLSScheme + "://" + hostPort,
			tlsConfig: &tls.Config{ServerName: serverName},
			wantHost:  "frostfs.example.com:8080",
			wantTLS:   true,
		},
		{
			uri:       "wrongScheme://" + hostPort,
			tlsConfig: nil,
			wantHost:  "",
			wantTLS:   false,
		},
		{
			uri:       "impossibleToParseIt",
			tlsConfig: nil,
			wantHost:  "impossibleToParseIt",
			wantTLS:   false,
		},
		{
			uri:       hostPort,
			tlsConfig: nil,
			wantHost:  hostPort,
			wantTLS:   false,
		},
		{
			uri:       apiPort,
			tlsConfig: nil,
			wantHost:  apiPort,
			wantTLS:   false,
		},
	}

	for _, test := range testCases {
		cfg := &cfg{}
		opts := WithNetworkURIAddress(test.uri, test.tlsConfig)

		for _, opt := range opts {
			opt(cfg)
		}

		require.Equal(t, test.wantHost, cfg.addr, test.uri)
		require.Equal(t, test.wantTLS, cfg.tlsCfg != nil, test.uri)
		// check if custom tlsConfig was applied
		if test.tlsConfig != nil && test.wantTLS {
			require.Equal(t, test.tlsConfig.ServerName, cfg.tlsCfg.ServerName, test.uri)
		}
	}
}

func Test_WithNetworkAddress_WithTLS_WithNetworkURIAddress(t *testing.T) {
	addr1, addr2 := "example1.com:8080", "example2.com:8080"

	testCases := []struct {
		addr    string
		withTLS bool

		uri string

		wantHost string
		wantTLS  bool
	}{
		{
			addr:    addr1,
			withTLS: true,

			uri: grpcScheme + "://" + addr2,

			wantHost: addr2,
			wantTLS:  false,
		},
		{
			addr:    addr1,
			withTLS: false,

			uri: grpcTLSScheme + "://" + addr2,

			wantHost: addr2,
			wantTLS:  true,
		},
	}

	for _, test := range testCases {
		// order:
		// 1. WithNetworkAddress
		// 2. WithTLSCfg(if test.withTLS == true)
		// 3. WithNetworkURIAddress
		config := &cfg{}
		opts := []Option{WithNetworkAddress(test.addr)}

		if test.withTLS {
			opts = append(opts, WithTLSCfg(&tls.Config{}))
		}

		opts = append(opts, WithNetworkURIAddress(test.uri, nil)...)

		for _, opt := range opts {
			opt(config)
		}

		require.Equal(t, test.wantHost, config.addr, test.addr)
		require.Equal(t, test.wantTLS, config.tlsCfg != nil, test.addr)
	}
}

func Test_WithNetworkURIAddress_WithTLS_WithNetworkAddress(t *testing.T) {
	addr1, addr2 := "example1.com:8080", "example2.com:8080"

	testCases := []struct {
		addr    string
		withTLS bool

		uri string

		wantHost string
		wantTLS  bool
	}{
		{
			uri: grpcScheme + "://" + addr1,

			addr:    addr2,
			withTLS: true,

			wantHost: addr2,
			wantTLS:  true,
		},
		{
			uri: grpcTLSScheme + "://" + addr1,

			addr:    addr2,
			withTLS: false,

			wantHost: addr2,
			wantTLS:  true,
		},
	}

	for _, test := range testCases {
		// order:
		// 1. WithNetworkURIAddress
		// 2. WithNetworkAddress
		// 3. WithTLSCfg(if test.withTLS == true)
		config := &cfg{}
		opts := WithNetworkURIAddress(test.uri, nil)

		opts = append(opts, WithNetworkAddress(test.addr))

		if test.withTLS {
			opts = append(opts, WithTLSCfg(&tls.Config{}))
		}

		for _, opt := range opts {
			opt(config)
		}

		require.Equal(t, test.wantHost, config.addr, test.uri)
		require.Equal(t, test.wantTLS, config.tlsCfg != nil, test.uri)
	}
}
