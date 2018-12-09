package handlers

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/globocom/gsh/types"
	"github.com/labstack/echo"
	"golang.org/x/crypto/ssh"
)

// certConfig is the struct that represents a certificate config
type certConfig struct {
	certType    uint32
	command     string
	extensions  map[string]string
	keyID       string
	principals  []string
	srcAddr     string
	validAfter  time.Time
	validBefore time.Time
}

// CertCreate create a certificate for user login
// - Input JSON sample:
// {
// 	"capacity": 1,
// 	"date_end": "2017-10-14T21:15:00-02:00",
// 	"date_open": "2017-10-14T11:30:00-02:00",
// 	"date_start": "2017-10-14T16:30:00-02:00",
// 	"description": "ENTRADA: Alface Crespa",
// 	"ou": "CT",
// 	"qtd": 800,
// 	"status": "OPEN",
// 	"type": "Jantar"
// }
//
// - Output JSON sample
// {
//     "id": "132",
//     "result": "success",
//     "tickets": 10
// }
///////////////////////////////////////////////////////////////////////////////
func (h AppHandler) CertCreate(c echo.Context) error {
	initTime := time.Now().UnixNano()

	// Importing data requested in types.CertRequest struct
	certRequest := new(types.CertRequest)
	if err := c.Bind(certRequest); err != nil {
		finishTime := time.Now().UnixNano()
		duration := float64((finishTime - initTime) / int64(time.Nanosecond))
		h.logChannel <- map[string]interface{}{
			"_owner":        c.Get("subject"),
			"_audience":     c.Get("audience"),
			"_jti":          c.Get("jti"),
			"_rid":          c.Get(echo.HeaderXRequestID),
			"_real-ip":      c.RealIP(),
			"_action":       "QueuesCreate.Bind",
			"_result":       "fail",
			"_duration":     duration,
			"short_message": err.Error,
		}
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Importing data requested in types.CertRequest struct", "details": err.Error()})
	}

	// Set our certificate validity times
	certRequest.ValidAfter = time.Now().Add(-30 * time.Second)
	certRequest.ValidBefore = time.Now().Add(600 * time.Second)

	// Parse user key
	var err error
	certRequest.PublicKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(certRequest.Key))
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Parse user key", "details": err.Error()})
	}

	// Using md5 because that's what ssh-keygen prints out, making searches for a particular key easier
	userFingerprint := ssh.FingerprintLegacyMD5(certRequest.PublicKey)

	// Parse the private key
	sshCASigner, err := ssh.ParsePrivateKey([]byte(h.config.GetString("CA_PRIVATE_KEY")))
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Parse user key", "details": err.Error()})
	}
	// Parse the public key
	certRequest.CAPublicKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(h.config.GetString("CA_PUBLIC_KEY")))
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Parse the public key", "details": err.Error()})
	}
	// Get the key's fingerprint for logging
	certRequest.CAFingerprint = ssh.FingerprintSHA256(certRequest.CAPublicKey)

	// Generate our key_id for the certificate
	certRequest.KeyID = fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] ca[%s] valid to[%s]", certRequest.User, certRequest.UserIP, certRequest.Command, userFingerprint, []byte(certRequest.CAFingerprint), certRequest.ValidBefore.Format(time.RFC3339))

	// Set all of our certificate options
	cc := certConfig{
		certType:    ssh.UserCert,
		command:     certRequest.Command,
		extensions:  map[string]string{"permit-pty": ""},
		keyID:       certRequest.KeyID,
		principals:  []string{certRequest.RemoteUser},
		srcAddr:     certRequest.BastionIP,
		validAfter:  certRequest.ValidAfter,
		validBefore: certRequest.ValidBefore,
	}

	// Get/update our ssh cert serial number
	criticalOptions := make(map[string]string)
	if cc.command != "" {
		criticalOptions["force-command"] = cc.command
	}
	criticalOptions["source-address"] = cc.srcAddr

	perms := ssh.Permissions{
		CriticalOptions: criticalOptions,
		Extensions:      cc.extensions,
	}

	// Make a cert from our pubkey
	cert := &ssh.Certificate{
		Key:             certRequest.PublicKey,
		Serial:          0,
		CertType:        cc.certType,
		KeyId:           cc.keyID,
		ValidPrincipals: cc.principals,
		ValidAfter:      uint64(cc.validAfter.Unix()),
		ValidBefore:     uint64(cc.validBefore.Unix()),
		Permissions:     perms,
	}

	// Sign user key
	err = cert.SignCert(rand.Reader, sshCASigner)
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Sign user key", "details": err.Error()})
	}
	signedKey := ssh.MarshalAuthorizedKey(cert)

	return c.String(http.StatusOK, string(signedKey))
}
