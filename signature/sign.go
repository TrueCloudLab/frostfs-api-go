package signature

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/signature"
	"golang.org/x/sync/errgroup"
)

type serviceRequest interface {
	GetMetaHeader() *session.RequestMetaHeader
	GetVerificationHeader() *session.RequestVerificationHeader
	SetVerificationHeader(*session.RequestVerificationHeader)
}

type serviceResponse interface {
	GetMetaHeader() *session.ResponseMetaHeader
	GetVerificationHeader() *session.ResponseVerificationHeader
	SetVerificationHeader(*session.ResponseVerificationHeader)
}

type signatureReceiver interface {
	SetBodySignature(*refs.Signature)
	SetMetaSignature(*refs.Signature)
	SetOriginSignature(*refs.Signature)
}

// SignServiceMessage signes service message with key.
func SignServiceMessage(key *ecdsa.PrivateKey, msg interface{}) error {
	switch v := msg.(type) {
	case nil:
		return nil
	case serviceRequest:
		return signServiceRequest(key, v)
	case serviceResponse:
		return signServiceResponse(key, v)
	default:
		panic(fmt.Sprintf("unsupported session message %T", v))
	}
}

func signServiceRequest(key *ecdsa.PrivateKey, v serviceRequest) error {
	result := &session.RequestVerificationHeader{}
	body := serviceMessageBody(v)
	meta := v.GetMetaHeader()
	header := v.GetVerificationHeader()
	if err := signMessageParts(key, body, meta, header, header != nil, result); err != nil {
		return err
	}
	result.SetOrigin(header)
	v.SetVerificationHeader(result)
	return nil
}

func signServiceResponse(key *ecdsa.PrivateKey, v serviceResponse) error {
	result := &session.ResponseVerificationHeader{}
	body := serviceMessageBody(v)
	meta := v.GetMetaHeader()
	header := v.GetVerificationHeader()
	if err := signMessageParts(key, body, meta, header, header != nil, result); err != nil {
		return err
	}
	result.SetOrigin(header)
	v.SetVerificationHeader(result)
	return nil
}

func signMessageParts(key *ecdsa.PrivateKey, body, meta, header stableMarshaler, hasHeader bool, result signatureReceiver) error {
	eg := &errgroup.Group{}
	if !hasHeader {
		// sign session message body
		eg.Go(func() error {
			if err := signServiceMessagePart(key, body, result.SetBodySignature); err != nil {
				return fmt.Errorf("could not sign body: %w", err)
			}
			return nil
		})
	}

	// sign meta header
	eg.Go(func() error {
		if err := signServiceMessagePart(key, meta, result.SetMetaSignature); err != nil {
			return fmt.Errorf("could not sign meta header: %w", err)
		}
		return nil
	})

	// sign verification header origin
	eg.Go(func() error {
		if err := signServiceMessagePart(key, header, result.SetOriginSignature); err != nil {
			return fmt.Errorf("could not sign origin of verification header: %w", err)
		}
		return nil
	})
	return eg.Wait()
}

func signServiceMessagePart(key *ecdsa.PrivateKey, part stableMarshaler, sigWrite func(*refs.Signature)) error {
	var sig *refs.Signature

	// sign part
	if err := signature.SignDataWithHandler(
		key,
		&StableMarshalerWrapper{part},
		func(s *refs.Signature) {
			sig = s
		},
	); err != nil {
		return err
	}

	// write part signature
	sigWrite(sig)

	return nil
}
