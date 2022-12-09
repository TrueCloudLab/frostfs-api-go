package reputation

import (
	reputation "github.com/TrueCloudLab/frostfs-api-go/v2/reputation/grpc"
	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
)

func (x *PeerID) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(x)
}

func (x *PeerID) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(x, data, new(reputation.PeerID))
}

func (x *Trust) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(x)
}

func (x *Trust) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(x, data, new(reputation.Trust))
}

func (x *PeerToPeerTrust) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(x)
}

func (x *PeerToPeerTrust) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(x, data, new(reputation.PeerToPeerTrust))
}

func (x *GlobalTrust) MarshalJSON() ([]byte, error) {
	return message.MarshalJSON(x)
}

func (x *GlobalTrust) UnmarshalJSON(data []byte) error {
	return message.UnmarshalJSON(x, data, new(reputation.GlobalTrust))
}
