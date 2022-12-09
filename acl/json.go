package acl

import (
	acl "github.com/TrueCloudLab/frostfs-api-go/v2/acl/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (f *HeaderFilter) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(f)
}

func (f *HeaderFilter) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(f, data, new(acl.EACLRecord_Filter))
}

func (t *Target) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(t)
}

func (t *Target) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(t, data, new(acl.EACLRecord_Target))
}

func (r *Record) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(r)
}

func (r *Record) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(r, data, new(acl.EACLRecord))
}

func (t *Table) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(t)
}

func (t *Table) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(t, data, new(acl.EACLTable))
}

func (l *TokenLifetime) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(l)
}

func (l *TokenLifetime) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(l, data, new(acl.BearerToken_Body_TokenLifetime))
}

func (bt *BearerTokenBody) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(bt)
}

func (bt *BearerTokenBody) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(bt, data, new(acl.BearerToken_Body))
}

func (bt *BearerToken) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(bt)
}

func (bt *BearerToken) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(bt, data, new(acl.BearerToken))
}
