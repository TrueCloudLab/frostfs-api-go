package session

import (
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	session "github.com/TrueCloudLab/frostfs-api-go/v2/session/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

func (c *ObjectSessionContext) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(c)
}

func (c *ObjectSessionContext) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(c, data, new(session.ObjectSessionContext))
}

func (l *TokenLifetime) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(l)
}

func (l *TokenLifetime) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(l, data, new(session.SessionToken_Body_TokenLifetime))
}

func (t *TokenBody) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(t)
}

func (t *TokenBody) UnmarshalJSON(data []byte) error {
	msg := new(session.SessionToken_Body)

	if err := protojson.Unmarshal(data, msg); err != nil {
		return err
	}

	return t.FromGRPCMessage(msg)
}

func (t *Token) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(t)
}

func (t *Token) UnmarshalJSON(data []byte) error {
	msg := new(session.SessionToken)

	if err := protojson.Unmarshal(data, msg); err != nil {
		return err
	}

	return t.FromGRPCMessage(msg)
}

func (x *XHeader) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(x)
}

func (x *XHeader) UnmarshalJSON(data []byte) error {
	msg := new(session.XHeader)

	if err := protojson.Unmarshal(data, msg); err != nil {
		return err
	}

	return x.FromGRPCMessage(msg)
}

func (r *RequestMetaHeader) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(r)
}

func (r *RequestMetaHeader) UnmarshalJSON(data []byte) error {
	msg := new(session.RequestMetaHeader)

	if err := protojson.Unmarshal(data, msg); err != nil {
		return err
	}

	return r.FromGRPCMessage(msg)
}

func (r *RequestVerificationHeader) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(r)
}

func (r *RequestVerificationHeader) UnmarshalJSON(data []byte) error {
	msg := new(session.RequestVerificationHeader)

	if err := protojson.Unmarshal(data, msg); err != nil {
		return err
	}

	return r.FromGRPCMessage(msg)
}

func (r *ResponseMetaHeader) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(r)
}

func (r *ResponseMetaHeader) UnmarshalJSON(data []byte) error {
	msg := new(session.ResponseMetaHeader)

	if err := protojson.Unmarshal(data, msg); err != nil {
		return err
	}

	return r.FromGRPCMessage(msg)
}

func (r *ResponseVerificationHeader) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(r)
}

func (r *ResponseVerificationHeader) UnmarshalJSON(data []byte) error {
	msg := new(session.ResponseVerificationHeader)

	if err := protojson.Unmarshal(data, msg); err != nil {
		return err
	}

	return r.FromGRPCMessage(msg)
}

func (x *ContainerSessionContext) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(x)
}

func (x *ContainerSessionContext) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(x, data, new(session.ContainerSessionContext))
}
