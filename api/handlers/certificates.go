package handlers

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globocom/gsh/types"
	"github.com/gofrs/uuid"
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
// 	"key":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1sB8sL1RATWY04/aLHlRiIyBc59h+Vr+kcK/RL6yYcT3PqAvzTHMlstXKbG9g4P18+DriHbOxeXQXRL/FZAJTE/kBs4iW/C75gxfny4scEq3xyAepk8R+812UKBN9QDivU7+LJ67YrmrZo8OmfhhVhqqvH8wIrjc85WuEpmqK7FcMZblcS4SgDMuOr11PWx36VNd5XRnRM0gfp3WFh3SRVqKHoH/39VHPHMz7LHt360EwKu9yslV7J0Jj631tG3p3061Nit/VOed6vRdFSE3na5FIwDw+LNvFJR8ahmAUKk1aMllBcRH8oXksDw5YufB84CRIr0znO/+8SIgcKXLl manoel.junior@twofish.local",
// 	"remote_user":"jim",
//  "remote_host":"192.168.2.105",
// 	"user_ip":"192.168.2.5",
//	"jwt": "...."
// }
//
// - Output sample
// ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgvz
// 4Hjd5bR2H2ryXBjyTuGt+Uerg80LriH48MtyOyBIgAAAADAQABAAABAQC1sB8sL1RATWY04/aLHlRiI
// yBc59h+Vr+kcK/RL6yYcT3PqAvzTHMlstXKbG9g4P18+DriHbOxeXQXRL/FZAJTE/kBs4iW/C75gxfn
// y4scEq3xyAepk8R+812UKBN9QDivU7+LJ67YrmrZo8OmfhhVhqqvH8wIrjc85WuEpmqK7FcMZblcS4S
// gDMuOr11PWx36VNd5XRnRM0gfp3WFh3SRVqKHoH/39VHPHMz7LHt360EwKu9yslV7J0Jj631tG3p306
// 1Nit/VOed6vRdFSE3na5FIwDw+LNvFJR8ahmAUKk1aMllBcRH8oXksDw5YufB84CRIr0znO/+8SIgcK
// XLlAAAAAAAAAAAAAAABAAAAtXVzZXJbXSBmcm9tWzE5Mi4xNjguMi41XSBjb21tYW5kW10gc3NoS2V5
// WzgwOjI5OmY3OmZjOjFkOjFhOjdmOjRiOmM4OjJhOjJhOmUwOjA4OmU2OmQzOjMyXSBjYVtTSEEyNTY
// 6OU5zLzdHamwxVVFReXBodElLREdZZCtPeUJkVjVrWnNRK3lmaVhzdDg0Y10gdmFsaWQgdG9bMjAxOC
// 0xMi0wOVQyMTowNjozNS0wMjowMF0AAAAHAAAAA2ppbQAAAABcDZ2FAAAAAFwNn/sAAAAlAAAADnNvd
// XJjZS1hZGRyZXNzAAAADwAAAAsxOTIuMTY4LjIuNQAAABIAAAAKcGVybWl0LXB0eQAAAAAAAAAAAAAB
// FQAAAAdzc2gtcnNhAAAAASMAAAEBAPj/vg/zXKNBy+GjtW0dZfZ2LQUeCA5FhOiQPaCpKpLO7YMAA63
// Lb3KbGdDOAnTFS3K69dwA+oItlSO7aEkIfo7YNxCNb6tMIwoa6y3E1hdQI2N+lAhcg2lSQtbeKzpds7
// vvQ/j5UuSVWvRxBJZOCkXEHRaA7y8e2jWVHQg9kcDeTFCvcIj7AEkBPTUXQFJd/RxDWmiYPSdQ9FTq3
// 9y11jKk9YXsG2fjiZo1uenoWCBJi2DJ9gkE53ednJzGAKa7y2+KMHwbPhcuTm19YvtH31M9iF2JtkZx
// 5qXXeWlJ7HgkcY60j2bUfqBIlZH/dor4t6BHcBOAHbm32C4Xe4jSRVMAAAEPAAAAB3NzaC1yc2EAAAE
// Ap/sdFMyeo6Jbdu4R33pZiSuTBGyBash4SlK4PoVEiuWnN2UHVH6DAi84qzG+Qhho48YJYarDDxxbOx
// cDinQ2j15XU0V/vVeucS12UF06HG9r+J51u0KMA/3dN4WNG6GKDrzY5M5Uad7lWnDNtbjRnhPVPCxHg
// V5YQLO6k94+kaPZbR+bVWb5tAOMoC1XHBwwDNLDqUKs2C8lvEpJY0Mf7ag9SNSep0Q5isq97zY3CWwP
// CtpYTN9tkQpfn+Noe4H7yOP2mkpAs3i7j/u0+Zz6SHejy4A7HlGHfJvWrOyg8J0ZzBSl5ho5eAw4Lrt
// +xcTVkFgWWPcml7CFiGwFhbui4w==
//
func (h AppHandler) CertCreate(c echo.Context) error {
	initTime := time.Now()

	// Importing data requested in types.CertRequest struct
	certRequest := new(types.CertRequest)
	if err := c.Bind(certRequest); err != nil {
		finishTime := time.Now().UnixNano()
		duration := float64((finishTime - initTime.UnixNano()) / int64(time.Nanosecond))
		h.logChannel <- map[string]interface{}{
			"_owner":        c.Get("subject"),
			"_audience":     c.Get("audience"),
			"_jti":          c.Get("jti"),
			"_rid":          c.Get(echo.HeaderXRequestID),
			"_real-ip":      c.RealIP(),
			"_action":       "cert.create",
			"_result":       "fail",
			"_duration":     duration,
			"short_message": err.Error,
		}
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Importing data requested in types.CertRequest struct", "details": err.Error()})
	}
	//Validating JWT before any other action
	var err error
	authorization_header := c.Request().Header.Get("Authorization")
	if len(authorization_header) == 0 {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Authorization header not provided", "details": "Expecting Authorization: JWT id_token"})
	}
	jwt := strings.Split(authorization_header, "JWT")
	if len(jwt) != 2 {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Authorization header malformed", "details": "Expecting Authorization: JWT id_token"})
	}
	err = ValidateJwt(jwt[1], h.config)
	if err != nil {
		return c.JSON(http.StatusUnauthorized,
			map[string]string{"result": "fail", "message": "Failed validating JWT", "details": err.Error()})
	}
	//Initializing vault
	v := Vault{h.config.GetString("ca_authority.role_id"), h.config.GetString("VAULT_SECRET_ID"), h.config, ""}
	// Set our certificate validity times
	certRequest.ValidAfter = time.Now().Add(-30 * time.Second)
	certRequest.ValidBefore = time.Now().Add(h.config.GetDuration("CERT_DURATION"))
	// Parse user key
	certRequest.PublicKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(certRequest.Key))
	if err != nil {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "message": "Parse user key", "details": err.Error()})
	}

	// Using md5 because that's what ssh-keygen prints out, making searches for a particular key easier
	userFingerprint := ssh.FingerprintLegacyMD5(certRequest.PublicKey)

	//here is where differs from an external signer and a local signer
	if h.config.GetBool("ca_authority.external") {
		externalPubKey, err := v.GetExternalPublicKey()
		if err != nil {
			return c.JSON(http.StatusInternalServerError,
				map[string]string{"result": "fail", "message": "Error getting ssh ca public key", "details": err.Error()})
		}

		certRequest.CAPublicKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(externalPubKey))
		if err != nil {
			return c.JSON(http.StatusBadRequest,
				map[string]string{"result": "fail", "message": "Parse the ssh ca public key", "details": err.Error()})
		}

		certRequest.CAFingerprint = ssh.FingerprintSHA256(certRequest.CAPublicKey)

	} else {
		// Parse the public key
		certRequest.CAPublicKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(h.config.GetString("CA_PUBLIC_KEY")))
		if err != nil {
			return c.JSON(http.StatusBadRequest,
				map[string]string{"result": "fail", "message": "Parse the public key", "details": err.Error()})
		}

		// Get the key's fingerprint for logging
		certRequest.CAFingerprint = ssh.FingerprintSHA256(certRequest.CAPublicKey)

		// Generate our key_id for the certificate
		// TODO: verify to log user thats requested certificate (not RemoteUser)
		certRequest.KeyID = fmt.Sprintf("user[%s] from[%s] command[%s] sshKey[%s] ca[%s] valid to[%s]", certRequest.RemoteUser, certRequest.UserIP, certRequest.Command, userFingerprint, []byte(certRequest.CAFingerprint), certRequest.ValidBefore.Format(time.RFC3339))
	}
	// Get/update our ssh cert serial number
	criticalOptions := make(map[string]string)
	criticalOptions["force-command"] = certRequest.Command
	criticalOptions["source-address"] = certRequest.UserIP

	perms := ssh.Permissions{
		CriticalOptions: criticalOptions,
		Extensions:      map[string]string{"permit-pty": ""},
	}

	// Make a cert from our pubkey
	certRequest.UID = uuid.Must(uuid.NewV4())
	cert := &ssh.Certificate{
		Nonce:           certRequest.UID.Bytes(),
		Key:             certRequest.PublicKey,
		Serial:          0,
		CertType:        ssh.UserCert,
		KeyId:           certRequest.KeyID,
		ValidPrincipals: []string{certRequest.RemoteUser},
		ValidAfter:      uint64(certRequest.ValidAfter.Unix()),
		ValidBefore:     uint64(certRequest.ValidBefore.Unix()),
		Permissions:     perms,
	}
	var signedKey string
	// Sign user key
	if h.config.GetBool("ca_authority.external") {
		signedKey, err = v.SignSshCertificate(cert)
		if err != nil {
			return c.JSON(http.StatusBadRequest,
				map[string]string{"result": "fail", "message": "Sign user key", "details": err.Error()})
		}
	} else {
		// Parse the private key
		sshCASigner, err := ssh.ParsePrivateKey([]byte(h.config.GetString("CA_PRIVATE_KEY")))
		if err != nil {
			return c.JSON(http.StatusBadRequest,
				map[string]string{"result": "fail", "message": "Parse private ca key", "details": err.Error()})
		}
		err = cert.SignCert(rand.Reader, sshCASigner)
		if err != nil {
			return c.JSON(http.StatusBadRequest,
				map[string]string{"result": "fail", "message": "Sign user key", "details": err.Error()})
		}
		signedKey = string(ssh.MarshalAuthorizedKey(cert))
	}
	// storing certificate in database
	dbc := h.db.Create(certRequest)
	if h.db.NewRecord(certRequest) {
		return c.JSON(http.StatusBadRequest,
			map[string]string{"result": "fail", "details": dbc.Error.Error()})
	}

	// sending auditRecord
	finishTime := time.Now()
	go func() {
		h.auditChannel <- types.AuditRecord{
			UID:       uuid.Must(uuid.NewV4()),
			StartTime: initTime,
			EndTime:   finishTime,
			Kind:      "cert.create",
			TargetUID: certRequest.UID,
			TargetID:  certRequest.ID,
		}
	}()
	return c.JSON(http.StatusOK, map[string]string{"result": "success", "certificate": signedKey})
}

func (h AppHandler) PublicKey(c echo.Context) error {
	v := Vault{h.config.GetString("ca_authority.role_id"), h.config.GetString("VAULT_SECRET_ID"), h.config, ""}
	data, err := v.GetExternalPublicKey()
	if err != nil {
		return c.JSON(http.StatusInternalServerError,
			map[string]string{"result": "fail", "message": "Error getting ssh public key", "details": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"result": "success", "public_key": string(data)})
}
