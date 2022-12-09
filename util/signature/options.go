package signature

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/signature/walletconnect"
	crypto "github.com/TrueCloudLab/frostfs-crypto"
)

type cfg struct {
	schemeFixed bool
	scheme      refs.SignatureScheme
	buffer      []byte
}

func defaultCfg() *cfg {
	return new(cfg)
}

func verify(cfg *cfg, data []byte, sig *refs.Signature) error {
	if !cfg.schemeFixed {
		cfg.scheme = sig.GetScheme()
	}

	pub := crypto.UnmarshalPublicKey(sig.GetKey())
	if pub == nil {
		return crypto.ErrEmptyPublicKey
	}

	switch cfg.scheme {
	case refs.ECDSA_SHA512:
		return crypto.Verify(pub, data, sig.GetSign())
	case refs.ECDSA_RFC6979_SHA256:
		return crypto.VerifyRFC6979(pub, data, sig.GetSign())
	case refs.ECDSA_RFC6979_SHA256_WALLET_CONNECT:
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
		base64.StdEncoding.Encode(buf, data)
		if !walletconnect.Verify(pub, buf, sig.GetSign()) {
			return crypto.ErrInvalidSignature
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature scheme %s", cfg.scheme)
	}
}

func sign(cfg *cfg, key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	switch cfg.scheme {
	case refs.ECDSA_SHA512:
		return crypto.Sign(key, data)
	case refs.ECDSA_RFC6979_SHA256:
		return crypto.SignRFC6979(key, data)
	case refs.ECDSA_RFC6979_SHA256_WALLET_CONNECT:
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
		base64.StdEncoding.Encode(buf, data)
		return walletconnect.Sign(key, buf)
	default:
		panic(fmt.Sprintf("unsupported scheme %s", cfg.scheme))
	}
}

func SignWithRFC6979() SignOption {
	return func(c *cfg) {
		c.schemeFixed = true
		c.scheme = refs.ECDSA_RFC6979_SHA256
	}
}

// WithBuffer allows providing pre-allocated buffer for signature verification.
func WithBuffer(buf []byte) SignOption {
	return func(c *cfg) {
		c.buffer = buf
	}
}

func SignWithWalletConnect() SignOption {
	return func(c *cfg) {
		c.scheme = refs.ECDSA_RFC6979_SHA256_WALLET_CONNECT
	}
}
