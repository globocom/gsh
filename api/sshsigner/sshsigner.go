package sshsigner

import (
	"golang.org/x/crypto/ssh"
)

// SSHSigner is interface with functions that all signers must implement
type SSHSigner interface {
	IsConfigured() error
	SignUserSSHCertificate(c *ssh.Certificate) (string, error)
	GetCAPublicKey() (string, error)
}

// SignerFactory is a factory of supported signers
type SignerFactory func(conf map[string]string) (SSHSigner, error)

// signerFactories is a map with all supported signers
var signerFactories = make(map[string]SignerFactory)

// Register is responsible for register new SSHSigners at signerFactories map
func Register(name string, factory SignerFactory) {
	if factory == nil {
		panic("Signer factory does not exist (" + name + ")")
	}
	_, registered := signerFactories[name]
	if registered {
		// log.Errorf("Datastore factory %s already registered. Ignoring.", name)
	}
	signerFactories[name] = factory
}
