package signature

import (
	"crypto/ecdsa"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	crypto "github.com/TrueCloudLab/frostfs-crypto"
)

type DataSource interface {
	ReadSignedData([]byte) ([]byte, error)
	SignedDataSize() int
}

type DataWithSignature interface {
	DataSource
	GetSignature() *refs.Signature
	SetSignature(*refs.Signature)
}

type SignOption func(*cfg)

type KeySignatureHandler func(*refs.Signature)

type KeySignatureSource func() *refs.Signature

func SignDataWithHandler(key *ecdsa.PrivateKey, src DataSource, handler KeySignatureHandler, opts ...SignOption) error {
	if key == nil {
		return crypto.ErrEmptyPrivateKey
	}

	cfg := defaultCfg()

	for i := range opts {
		opts[i](cfg)
	}

	data, err := readSignedData(cfg, src)
	if err != nil {
		return err
	}

	sigData, err := sign(cfg, key, data)
	if err != nil {
		return err
	}

	sig := new(refs.Signature)
	sig.SetScheme(cfg.scheme)
	sig.SetKey(crypto.MarshalPublicKey(&key.PublicKey))
	sig.SetSign(sigData)
	handler(sig)

	return nil
}

func VerifyDataWithSource(dataSrc DataSource, sigSrc KeySignatureSource, opts ...SignOption) error {
	cfg := defaultCfg()

	for i := range opts {
		opts[i](cfg)
	}

	data, err := readSignedData(cfg, dataSrc)
	if err != nil {
		return err
	}

	return verify(cfg, data, sigSrc())
}

func SignData(key *ecdsa.PrivateKey, v DataWithSignature, opts ...SignOption) error {
	return SignDataWithHandler(key, v, v.SetSignature, opts...)
}

func VerifyData(src DataWithSignature, opts ...SignOption) error {
	return VerifyDataWithSource(src, src.GetSignature, opts...)
}

func readSignedData(cfg *cfg, src DataSource) ([]byte, error) {
	size := src.SignedDataSize()
	if cfg.buffer == nil || cap(cfg.buffer) < size {
		cfg.buffer = make([]byte, size)
	} else {
		cfg.buffer = cfg.buffer[:size]
	}
	return src.ReadSignedData(cfg.buffer)
}
