package signature

import (
	"errors"
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/signature"
	"golang.org/x/sync/errgroup"
)

type signatureProvider interface {
	GetBodySignature() *refs.Signature
	GetMetaSignature() *refs.Signature
	GetOriginSignature() *refs.Signature
}

type buffers struct {
	Body   []byte
	Meta   []byte
	Header []byte
}

// VerifyServiceMessage verifies service message.
func VerifyServiceMessage(msg interface{}) error {
	switch v := msg.(type) {
	case nil:
		return nil
	case serviceRequest:
		return verifyServiceRequest(v)
	case serviceResponse:
		return verifyServiceResponse(v)
	default:
		panic(fmt.Sprintf("unsupported session message %T", v))
	}
}

func verifyServiceRequest(v serviceRequest) error {
	meta := v.GetMetaHeader()
	verificationHeader := v.GetVerificationHeader()
	body := serviceMessageBody(v)
	buffers := createBuffers(body.StableSize(), meta.StableSize(), verificationHeader.StableSize())
	return verifyServiceRequestRecursive(body, meta, verificationHeader, buffers)
}

func createBuffers(bodySize, metaSize, headerSize int) *buffers {
	return &buffers{
		Body:   make([]byte, 0, bodySize),
		Meta:   make([]byte, 0, metaSize),
		Header: make([]byte, 0, headerSize),
	}
}

func verifyServiceRequestRecursive(body stableMarshaler, meta *session.RequestMetaHeader, verify *session.RequestVerificationHeader, buffers *buffers) error {
	verificationHeaderOrigin := verify.GetOrigin()
	metaOrigin := meta.GetOrigin()

	stop, err := verifyMessageParts(body, meta, verificationHeaderOrigin, verificationHeaderOrigin != nil, verify, buffers)
	if err != nil {
		return err
	}
	if stop {
		return nil
	}

	return verifyServiceRequestRecursive(body, metaOrigin, verificationHeaderOrigin, buffers)
}

func verifyMessageParts(body, meta, originHeader stableMarshaler, hasOriginHeader bool, sigProvider signatureProvider, buffers *buffers) (stop bool, err error) {
	eg := &errgroup.Group{}

	eg.Go(func() error {
		if err := verifyServiceMessagePart(meta, sigProvider.GetMetaSignature, buffers.Meta); err != nil {
			return fmt.Errorf("could not verify meta header: %w", err)
		}
		return nil
	})

	eg.Go(func() error {
		if err := verifyServiceMessagePart(originHeader, sigProvider.GetOriginSignature, buffers.Header); err != nil {
			return fmt.Errorf("could not verify origin of verification header: %w", err)
		}
		return nil
	})

	if !hasOriginHeader {
		eg.Go(func() error {
			if err := verifyServiceMessagePart(body, sigProvider.GetBodySignature, buffers.Body); err != nil {
				return fmt.Errorf("could not verify body: %w", err)
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return false, err
	}

	if !hasOriginHeader {
		return true, nil
	}

	if sigProvider.GetBodySignature() != nil {
		return false, errors.New("body signature misses at the matryoshka upper level")
	}

	return false, nil
}

func verifyServiceResponse(v serviceResponse) error {
	meta := v.GetMetaHeader()
	verificationHeader := v.GetVerificationHeader()
	body := serviceMessageBody(v)
	buffers := createBuffers(body.StableSize(), meta.StableSize(), verificationHeader.StableSize())
	return verifyServiceResponseRecursive(body, meta, verificationHeader, buffers)
}

func verifyServiceResponseRecursive(body stableMarshaler, meta *session.ResponseMetaHeader, verify *session.ResponseVerificationHeader, buffers *buffers) error {
	verificationHeaderOrigin := verify.GetOrigin()
	metaOrigin := meta.GetOrigin()

	stop, err := verifyMessageParts(body, meta, verificationHeaderOrigin, verificationHeaderOrigin != nil, verify, buffers)
	if err != nil {
		return err
	}
	if stop {
		return nil
	}

	return verifyServiceResponseRecursive(body, metaOrigin, verificationHeaderOrigin, buffers)
}

func verifyServiceMessagePart(part stableMarshaler, sigRdr func() *refs.Signature, buf []byte) error {
	return signature.VerifyDataWithSource(
		&StableMarshalerWrapper{part},
		sigRdr,
		signature.WithBuffer(buf),
	)
}
