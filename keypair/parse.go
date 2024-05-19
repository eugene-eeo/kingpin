package keypair

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func ParseKeyFile(path string) (*KeyPair, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKey(b)
}

func ParseKey(b []byte) (*KeyPair, error) {
	genericSk, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}
	sk, ok := genericSk.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 private key, got %+v", genericSk)
	}
	return &KeyPair{
		sk: *sk,
		pk: sk.Public().(ed25519.PublicKey),
	}, nil
}

func ParsePubKey(b []byte) (ssh.PublicKey, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}
	if pk.Type() != "ssh-ed25519" {
		return nil, fmt.Errorf("expected ed25519 public key, got %q", pk.Type())
	}
	return pk, nil
}
