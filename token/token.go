package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

var (
	hmacAlgo = sha256.New
	b64Enc   = base64.RawURLEncoding.EncodeToString
	b64Dec   = base64.RawURLEncoding.DecodeString

	InvalidToken = errors.New("invalid token")
	TokenExpired = errors.New("token has expired")
)

type Key []byte

func encodeTime(t time.Time) []byte {
	return binary.LittleEndian.AppendUint64(nil, uint64(t.Unix()))
}

func newWithExpiration(data []byte, key Key, validUntil time.Time) string {
	tBytes := encodeTime(validUntil)

	h := hmac.New(hmacAlgo, key)
	h.Write(tBytes)
	h.Write(data)

	mac := h.Sum(nil)
	tok := b64Enc(tBytes) + "." + b64Enc(data) + "." + b64Enc(mac)
	return tok
}

func New(data []byte, key Key, expiration time.Duration) string {
	return newWithExpiration(data, key, time.Now().Add(expiration))
}

func parseWithTime(s string, key Key, now time.Time) ([]byte, error) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return nil, InvalidToken
	}

	validUntilBytes, err := b64Dec(parts[0])
	if err != nil || len(validUntilBytes) != 8 {
		return nil, InvalidToken
	}
	validUntilUnix := binary.LittleEndian.Uint64(validUntilBytes)
	validUntil := time.Unix(int64(validUntilUnix), 0)
	if now.After(validUntil) {
		return nil, TokenExpired
	}

	data, err := b64Dec(parts[1])
	if err != nil {
		return nil, InvalidToken
	}

	gotMac, err := b64Dec(parts[2])
	if err != nil {
		return nil, InvalidToken
	}

	h := hmac.New(hmacAlgo, key)
	h.Write(validUntilBytes)
	h.Write(data)
	expectedMac := h.Sum(nil)
	if !hmac.Equal(gotMac, expectedMac) {
		return nil, InvalidToken
	}

	return data, nil
}

func Parse(s string, key Key) ([]byte, error) {
	return parseWithTime(s, key, time.Now())
}
