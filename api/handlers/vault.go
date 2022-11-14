package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// Vault store configuration to use remote Vault as cert signer
type Vault struct {
	roleID   string
	secretID string
	config   viper.Viper
	token    string
}

type authResponse struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
		Metadata      struct {
			RoleName string `json:"role_name"`
		} `json:"metadata"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		EntityID      string `json:"entity_id"`
		TokenType     string `json:"token_type"`
	} `json:"auth"`
}

type sshCertificate struct {
	LeaseID       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		SerialNumber string `json:"serial_number"`
		SignedKey    string `json:"signed_key"`
	} `json:"data"`
	Auth interface{} `json:"auth"`
}

// GetVault returns Vault configuration
func GetVault() Vault {
	return Vault{}
}

// GetToken autenticate on Vault instance and returns a client token
func (v *Vault) GetToken() error {
	data := make(map[string]string)
	data["role_id"] = v.roleID
	data["secret_id"] = v.secretID
	jsonData, _ := json.Marshal(data)
	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
	}
	req, _ := http.NewRequest("POST", v.config.GetString("ca_endpoint")+v.config.GetString("ca_login_url"), bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("Failed to authenticate with vault: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("Failed to authenticate with vault: status code " + strconv.Itoa(resp.StatusCode))
	}
	authResponse := authResponse{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&authResponse)
	if err != nil {
		return errors.New("Failed to decode Vault token (" + err.Error() + ")")
	}

	v.token = authResponse.Auth.ClientToken

	return nil
}

// SignUserSSHCertificate sign ssh.Certificate for user and return a string with data (without \n at end)
func (v *Vault) SignUserSSHCertificate(c *ssh.Certificate) (string, error) {
	// get new vault client token
	err := v.GetToken()
	if err != nil {
		return "", errors.New("Failed to get Vault token (" + err.Error() + ")")
	}

	// set Vault data struct for sign
	data := make(map[string]string)
	data["public_key"] = string(ssh.MarshalAuthorizedKey(c.Key))
	data["valid_principals"] = strings.Join(c.ValidPrincipals, ",")
	data["cert_type"] = "user"

	// request vault
	jsonData, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", v.config.GetString("ca_endpoint")+v.config.GetString("ca_signer_url"), bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", v.token)
	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Failed to sign SSH certificate")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Failed to sign SSH certificate, not 200 ok")
	}

	// parse Vault response
	sshCertificate := sshCertificate{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&sshCertificate)
	if err != nil {
		return "", errors.New("Failed to decode SSH certificate (" + err.Error() + ")")
	}

	return strings.TrimSuffix(sshCertificate.Data.SignedKey, "\n"), nil
}

// GetExternalPublicKey returns public key from external CA
func (v *Vault) GetExternalPublicKey() (string, error) {
	resp, err := http.Get(v.config.GetString("ca_endpoint") + v.config.GetString("ca_public_key_url"))
	if err != nil {
		return "-1", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("External CA did not respond correctly: status code " + strconv.Itoa(resp.StatusCode))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
