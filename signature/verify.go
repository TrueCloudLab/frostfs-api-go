package signature

import (
	"errors"
	"fmt"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	"github.com/TrueCloudLab/frostfs-api-go/v2/session"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/collection"
	"github.com/TrueCloudLab/frostfs-api-go/v2/util/signature"
)

type signatureProvider interface {
	GetBodySignature() *refs.Signature
	GetMetaSignature() *refs.Signature
	GetOriginSignature() *refs.Signature
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
	size := collection.Max(body.StableSize(), meta.StableSize(), verificationHeader.StableSize())
	buf := make([]byte, 0, size)
	return verifyServiceRequestRecursive(body, meta, verificationHeader, buf)
}

func verifyServiceRequestRecursive(body stableMarshaler, meta *session.RequestMetaHeader, verify *session.RequestVerificationHeader, buf []byte) error {
	verificationHeaderOrigin := verify.GetOrigin()
	metaOrigin := meta.GetOrigin()

	stop, err := verifyMessageParts(body, meta, verificationHeaderOrigin, verificationHeaderOrigin != nil, verify, buf)
	if err != nil {
		return err
	}
	if stop {
		return nil
	}

	return verifyServiceRequestRecursive(body, metaOrigin, verificationHeaderOrigin, buf)
}

func verifyMessageParts(body, meta, originHeader stableMarshaler, hasOriginHeader bool, sigProvider signatureProvider, buf []byte) (stop bool, err error) {
	if err := verifyServiceMessagePart(meta, sigProvider.GetMetaSignature, buf); err != nil {
		return false, fmt.Errorf("could not verify meta header: %w", err)
	}

	if err := verifyServiceMessagePart(originHeader, sigProvider.GetOriginSignature, buf); err != nil {
		return false, fmt.Errorf("could not verify origin of verification header: %w", err)
	}

	if !hasOriginHeader {
		if err := verifyServiceMessagePart(body, sigProvider.GetBodySignature, buf); err != nil {
			return false, fmt.Errorf("could not verify body: %w", err)
		}

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
	size := collection.Max(body.StableSize(), meta.StableSize(), verificationHeader.StableSize())
	buf := make([]byte, 0, size)
	return verifyServiceResponseRecursive(body, meta, verificationHeader, buf)
}

func verifyServiceResponseRecursive(body stableMarshaler, meta *session.ResponseMetaHeader, verify *session.ResponseVerificationHeader, buf []byte) error {
	verificationHeaderOrigin := verify.GetOrigin()
	metaOrigin := meta.GetOrigin()

	stop, err := verifyMessageParts(body, meta, verificationHeaderOrigin, verificationHeaderOrigin != nil, verify, buf)
	if err != nil {
		return err
	}
	if stop {
		return nil
	}

	return verifyServiceResponseRecursive(body, metaOrigin, verificationHeaderOrigin, buf)
}

func verifyServiceMessagePart(part stableMarshaler, sigRdr func() *refs.Signature, buf []byte) error {
	return signature.VerifyDataWithSource(
		&StableMarshalerWrapper{part},
		sigRdr,
		signature.WithBuffer(buf),
	)
}
