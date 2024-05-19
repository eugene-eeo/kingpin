package keypair

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	InvalidRequest = errors.New("invalid request")
	// standard user-key permissions from ssh-keygen
	userPermissions = []string{
		"permit-X11-forwarding",
		"permit-agent-forwarding",
		"permit-port-forwarding",
		"permit-pty",
		"permit-user-rc",
	}
)

// Request represents a certificate signing request.
type Request struct {
	UserKey    bool     `json:"user_key"`
	Principals []string `json:"principals"`

	// From and To is the number of seconds.
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

func (r *Request) Validate() error {
	if len(r.Principals) == 0 {
		return fmt.Errorf("%w: principals is empty", InvalidRequest)
	}
	return nil
}

func (r *Request) Encode() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	return b
}

func (r *Request) sshCert(pk ssh.PublicKey) *ssh.Certificate {
	now := time.Now()
	cert := &ssh.Certificate{
		KeyId:           r.Principals[0],
		Key:             pk,
		ValidPrincipals: r.Principals,
		CertType:        ssh.HostCert,
		ValidAfter:      uint64(now.Add(time.Duration(r.From) * time.Second).Unix()),
		ValidBefore:     uint64(now.Add(time.Duration(r.To) * time.Second).Unix()),
	}

	if r.UserKey {
		cert.CertType = ssh.UserCert
		extensions := map[string]string{}
		for _, perm := range userPermissions {
			extensions[perm] = ""
		}
		cert.Permissions = ssh.Permissions{Extensions: extensions}
	}
	return cert
}
