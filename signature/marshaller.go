package signature

type stableMarshaler interface {
	StableMarshal([]byte) []byte
	StableSize() int
}

type StableMarshalerWrapper struct {
	SM stableMarshaler
}

func (s StableMarshalerWrapper) ReadSignedData(buf []byte) ([]byte, error) {
	if s.SM != nil {
		return s.SM.StableMarshal(buf), nil
	}

	return nil, nil
}

func (s StableMarshalerWrapper) SignedDataSize() int {
	if s.SM != nil {
		return s.SM.StableSize()
	}

	return 0
}
