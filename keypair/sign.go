package keypair

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/ssh"
)

var (
	InvalidPrincipals = errors.New("invalid principals")
)

// KeyPair is an Ed25519 keypair.
type KeyPair struct {
	sk ed25519.PrivateKey
	pk ed25519.PublicKey
}

// PublicKey returns the public key in OpenSSH format.
func (kp *KeyPair) PublicKey() []byte {
	sshPk, err := ssh.NewPublicKey(kp.pk)
	if err != nil {
		panic(err)
	}
	return ssh.MarshalAuthorizedKey(sshPk)
}

// Sign signs the given public key with the CA, with details generated from
// the request.
func Sign(r *Request, ca *KeyPair, pk ssh.PublicKey) ([]byte, error) {
	signer, err := ssh.NewSignerFromKey(ca.sk)
	if err != nil {
		return nil, err
	}
	cert := r.cert(pk)
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}
