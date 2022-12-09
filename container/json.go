package container

import (
	container "github.com/TrueCloudLab/frostfs-api-go/v2/container/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (a *Attribute) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(a)
}

func (a *Attribute) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(a, data, new(container.Container_Attribute))
}

func (c *Container) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(c)
}

func (c *Container) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(c, data, new(container.Container))
}
