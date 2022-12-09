package object

import (
	object "github.com/TrueCloudLab/frostfs-api-go/v2/object/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (h *ShortHeader) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(h)
}

func (h *ShortHeader) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(h, data, new(object.ShortHeader))
}

func (a *Attribute) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(a)
}

func (a *Attribute) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(a, data, new(object.Header_Attribute))
}

func (h *SplitHeader) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(h)
}

func (h *SplitHeader) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(h, data, new(object.Header_Split))
}

func (h *Header) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(h)
}

func (h *Header) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(h, data, new(object.Header))
}

func (h *HeaderWithSignature) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(h)
}

func (h *HeaderWithSignature) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(h, data, new(object.HeaderWithSignature))
}

func (o *Object) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(o)
}

func (o *Object) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(o, data, new(object.Object))
}

func (s *SplitInfo) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(s)
}

func (s *SplitInfo) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(s, data, new(object.SplitInfo))
}

func (f *SearchFilter) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(f)
}

func (f *SearchFilter) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(f, data, new(object.SearchRequest_Body_Filter))
}

func (r *Range) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(r)
}

func (r *Range) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(r, data, new(object.Range))
}
