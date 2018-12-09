package types

import (
	"time"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/ssh"
)

// CertRequest is the struct that represents a certificate request
type CertRequest struct {
	UID         uuid.UUID `json:"uid,omitempty"`
	BastionIP   string    `json:"bastion_ip,omitempty"`
	BastionUser string    `json:"bastion_user,omitempty"`
	Command     string    `json:"command,omitempty"`
	CSR         string    `json:"csr,omitempty"`
	Key         string    `json:"key,omitempty"`
	RemoteUser  string    `json:"remote_user,omitempty"`
	UserIP      string    `json:"user_ip,omitempty"`

	// user is authenticaded user
	User        string
	ValidAfter  time.Time
	ValidBefore time.Time
	PublicKey   ssh.PublicKey

	// CA used in certificate sign
	CAPublicKey   ssh.PublicKey
	CAFingerprint string
	KeyID         string
}
