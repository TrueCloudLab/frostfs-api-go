package walletconnect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"

	crypto "github.com/TrueCloudLab/frostfs-crypto"
)

const (
	// saltSize is the salt size added to signed message.
	saltSize = 16
	// signatureLen is the length of RFC6979 signature.
	signatureLen = 64
)

// SignedMessage contains mirrors `SignedMessage` struct from the WalletConnect API.
// https://neon.coz.io/wksdk/core/modules.html#SignedMessage
type SignedMessage struct {
	Data      []byte
	Message   []byte
	PublicKey []byte
	Salt      []byte
}

// Sign signs message using WalletConnect API. The returned signature
// contains RFC6979 signature and 16-byte salt.
func Sign(p *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	sm, err := SignMessage(p, msg)
	if err != nil {
		return nil, err
	}
	return append(sm.Data, sm.Salt...), nil
}

// Verify verifies message using WalletConnect API.
func Verify(p *ecdsa.PublicKey, data, sign []byte) bool {
	if len(sign) != signatureLen+saltSize {
		return false
	}

	salt := sign[signatureLen:]
	return VerifyMessage(p, SignedMessage{
		Data:    sign[:signatureLen],
		Message: createMessageWithSalt(data, salt),
		Salt:    salt,
	})
}

// SignMessage signs message with a private key and returns structure similar to
// `signMessage` of the WalletConnect API.
// https://github.com/CityOfZion/wallet-connect-sdk/blob/89c236b/packages/wallet-connect-sdk-core/src/index.ts#L496
// https://github.com/CityOfZion/neon-wallet/blob/1174a9388480e6bbc4f79eb13183c2a573f67ca8/app/context/WalletConnect/helpers.js#L133
func SignMessage(p *ecdsa.PrivateKey, msg []byte) (SignedMessage, error) {
	var salt [saltSize]byte
	_, _ = rand.Read(salt[:])

	msg = createMessageWithSalt(msg, salt[:])
	sign, err := crypto.SignRFC6979(p, msg)
	if err != nil {
		return SignedMessage{}, err
	}

	return SignedMessage{
		Data:      sign,
		Message:   msg,
		PublicKey: elliptic.MarshalCompressed(p.Curve, p.X, p.Y),
		Salt:      salt[:],
	}, nil
}

// VerifyMessage verifies message with a private key and returns structure similar to
// `verifyMessage` of WalletConnect API.
// https://github.com/CityOfZion/wallet-connect-sdk/blob/89c236b/packages/wallet-connect-sdk-core/src/index.ts#L515
// https://github.com/CityOfZion/neon-wallet/blob/1174a9388480e6bbc4f79eb13183c2a573f67ca8/app/context/WalletConnect/helpers.js#L147
func VerifyMessage(p *ecdsa.PublicKey, m SignedMessage) bool {
	if p == nil {
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), m.PublicKey)
		if x == nil || y == nil {
			return false
		}
		p = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
	}
	return crypto.VerifyRFC6979(p, m.Message, m.Data) == nil
}

func createMessageWithSalt(msg, salt []byte) []byte {
	// 4 byte prefix + length of the message with salt in bytes +
	// + salt + message + 2 byte postfix.
	saltedLen := hex.EncodedLen(len(salt)) + len(msg)
	data := make([]byte, 4+getVarIntSize(saltedLen)+saltedLen+2)

	n := copy(data, []byte{0x01, 0x00, 0x01, 0xf0}) // fixed prefix
	n += putVarUint(data[n:], uint64(saltedLen))    // salt is hex encoded, double its size
	n += hex.Encode(data[n:], salt[:])              // for some reason we encode salt in hex
	n += copy(data[n:], msg)
	copy(data[n:], []byte{0x00, 0x00})

	return data
}

// Following functions are copied from github.com/nspcc-dev/neo-go/pkg/io package
// to avoid having another dependency.

// getVarIntSize returns the size in number of bytes of a variable integer.
// Reference: https://github.com/neo-project/neo/blob/26d04a642ac5a1dd1827dabf5602767e0acba25c/src/neo/IO/Helper.cs#L131
func getVarIntSize(value int) int {
	var size uintptr

	if value < 0xFD {
		size = 1 // unit8
	} else if value <= 0xFFFF {
		size = 3 // byte + uint16
	} else {
		size = 5 // byte + uint32
	}
	return int(size)
}

// putVarUint puts val in varint form to the pre-allocated buffer.
func putVarUint(data []byte, val uint64) int {
	if val < 0xfd {
		data[0] = byte(val)
		return 1
	}
	if val <= 0xFFFF {
		data[0] = byte(0xfd)
		binary.LittleEndian.PutUint16(data[1:], uint16(val))
		return 3
	}

	data[0] = byte(0xfe)
	binary.LittleEndian.PutUint32(data[1:], uint32(val))
	return 5
}
