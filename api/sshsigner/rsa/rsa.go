package rsa

import (
	"crypto/rand"
	"fmt"

	"github.com/globocom/gsh/api/sshsigner"
	"golang.org/x/crypto/ssh"
)

// RSA implement functions at sshsigner interface
type RSA struct {
	CAPrivateKey []byte
	CAPublicKey  []byte
}

// NewSSHSigner is an construtor for for RSA Signer
func NewSSHSigner(conf map[string]string) (sshsigner.SSHSigner, error) {
	return &RSA{}, nil
}

func init() {
	sshsigner.Register("rsa", NewSSHSigner)
}

// RSA.CAPrivateKey = []byte(h.config.GetString("ca_private_key"))

// SignUserSSHCertificate receives an ssh.Certificate for user and return a string with data (without \n at end)
func (rsa *RSA) SignUserSSHCertificate(cert *ssh.Certificate) (string, error) {
	// Parse the private key
	sshCASigner, err := ssh.ParsePrivateKey(rsa.CAPrivateKey)
	if err != nil {
		return "", fmt.Errorf("RSA SignUserSSHCertificate: error parsing ca key (%v)", err.Error())
	}

	err = cert.SignCert(rand.Reader, sshCASigner)
	if err != nil {
		return "", fmt.Errorf("RSA SignUserSSHCertificate: error sign user key (%v)", err.Error())
	}
	signedKey := string(ssh.MarshalAuthorizedKey(cert))

	return signedKey, nil
}

// GetCAPublicKey returns public key from CA
func (rsa *RSA) GetCAPublicKey() (string, error) {
	if len(rsa.CAPublicKey) == 0 {
		return "", fmt.Errorf("RSA GetCAPublicKey: error getting CA public key")
	}
	return string(rsa.CAPublicKey), nil
}

// IsConfigured returns if CA is configured
func (rsa *RSA) IsConfigured() error {
	if len(rsa.CAPublicKey) == 0 {
		return fmt.Errorf("RSA IsConfigured: error getting CA public key")
	}
	if len(rsa.CAPrivateKey) == 0 {
		return fmt.Errorf("RSA IsConfigured: error getting CA private key")
	}
	return nil
}
