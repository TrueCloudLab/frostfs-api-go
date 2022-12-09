package refs

import (
	refs "github.com/TrueCloudLab/frostfs-api-go/v2/refs/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (a *Address) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(a)
}

func (a *Address) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(a, data, new(refs.Address))
}

func (o *ObjectID) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(o)
}

func (o *ObjectID) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(o, data, new(refs.ObjectID))
}

func (c *ContainerID) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(c)
}

func (c *ContainerID) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(c, data, new(refs.ContainerID))
}

func (o *OwnerID) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(o)
}

func (o *OwnerID) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(o, data, new(refs.OwnerID))
}

func (v *Version) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(v)
}

func (v *Version) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(v, data, new(refs.Version))
}

func (s *Signature) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(s)
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(s, data, new(refs.Signature))
}

func (c *Checksum) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(c)
}

func (c *Checksum) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(c, data, new(refs.Checksum))
}
