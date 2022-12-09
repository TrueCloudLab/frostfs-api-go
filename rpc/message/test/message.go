package messagetest

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/TrueCloudLab/frostfs-api-go/v2/rpc/message"
	"github.com/stretchr/testify/require"
)

type jsonMessage interface {
	json.Marshaler
	json.Unmarshaler
}

type binaryMessage interface {
	StableMarshal([]byte) []byte
	Unmarshal([]byte) error
}

func TestRPCMessage(t *testing.T, msgGens ...func(empty bool) message.Message) {
	for _, msgGen := range msgGens {
		msg := msgGen(false)

		t.Run(fmt.Sprintf("convert_%T", msg), func(t *testing.T) {
			msg := msgGen(false)

			err := msg.FromGRPCMessage(100)

			require.True(t, errors.As(err, new(message.ErrUnexpectedMessageType)))

			msg2 := msgGen(true)

			err = msg2.FromGRPCMessage(msg.ToGRPCMessage())
			require.NoError(t, err)

			require.Equal(t, msg, msg2)
		})

		t.Run("encoding", func(t *testing.T) {
			if jm, ok := msg.(jsonMessage); ok {
				t.Run(fmt.Sprintf("JSON_%T", msg), func(t *testing.T) {
					data, err := jm.MarshalJSON()
					require.NoError(t, err)

					jm2 := msgGen(true).(jsonMessage)
					require.NoError(t, jm2.UnmarshalJSON(data))

					require.Equal(t, jm, jm2)
				})
			}

			if bm, ok := msg.(binaryMessage); ok {
				t.Run(fmt.Sprintf("Binary_%T", msg), func(t *testing.T) {
					data := bm.StableMarshal(nil)

					bm2 := msgGen(true).(binaryMessage)
					require.NoError(t, bm2.Unmarshal(data))

					require.Equal(t, bm, bm2)
				})
			}
		})
	}
}
