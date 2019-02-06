package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkPermissionCmd)
	checkPermissionCmd.Flags().String("key-id", "", "the key-id of the ssh certificate")
	checkPermissionCmd.Flags().String("username", "", "the username of the user trying to authenticate")
	checkPermissionCmd.Flags().String("api", "", "the endpoint GSH API to check certificate")
}

// CertInfo is struct with response for GET /certificate/:keyID
type CertInfo struct {
	Result     string `json:"result"`
	RemoteUser string `json:"remote_user"`
	RemoteHost string `json:"remote_host"`
}

var log = logrus.New()

// checkPermissionCmd represents the checkPermission command
var checkPermissionCmd = &cobra.Command{
	Use:   "check-permission",
	Short: "Check permissions from a new ssh authentication",
	Long: `
 Check permissions from a new ssh authentication, if one check fails it will deny the authentication.
 	`,
	Args: cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		//default log to stdout
		log.Out = os.Stdout

		// Check for log file
		logFile := "/var/log/gsh-audit.log"

		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			file, err := os.OpenFile(logFile, os.O_CREATE, 0600)
			if err != nil {
				log.Info("Failed to log to file, using default stdout")
			} else {
				file.Close()
			}
		}

		file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Info("Failed to log to file, using default stdout")
		} else {
			log.Out = file
			defer file.Close()
		}

		// Get key-id flag
		keyID, err := cmd.Flags().GetString("key-id")
		if err != nil {
			log.WithFields(logrus.Fields{
				"event":  "reading flag parameter from sshd",
				"topic":  "key-id not informed",
				"key":    "key-id",
				"result": "fail",
			}).Fatal("Failed to read key-id")
			os.Exit(-1)
		}

		// Get username flag
		username, err := cmd.Flags().GetString("username")
		if err != nil {
			log.WithFields(logrus.Fields{
				"event":  "reading flag parameter from sshd",
				"topic":  "username not informed",
				"key":    "username",
				"result": "fail",
			}).Fatal("Failed to read username")
			os.Exit(-1)
		}

		// Defining default field to log
		auditLogger := log.WithFields(logrus.Fields{"key_id": keyID, "username": username})

		// Get GSH API endpoint
		api, err := cmd.Flags().GetString("api")
		if err != nil {
			log.WithFields(logrus.Fields{
				"event":  "reading flag parameter from sshd",
				"topic":  "api endpoint not informed",
				"key":    "api",
				"result": "fail",
			}).Fatal("Failed to read api endpoint")
			os.Exit(-1)
		}

		// Get certificate from GSH API
		certInfo, err := getCertInfo(keyID, api)
		if err != nil {
			auditLogger.WithFields(logrus.Fields{
				"event":  "certinfo error validation",
				"topic":  "not possible verify certificate",
				"key":    "api",
				"result": "fail",
				"error":  err.Error(),
			}).Fatal("Not possible verify certificate")
			os.Exit(-1)
		}

		checkIfaces := checkInterfaces(certInfo.RemoteHost)
		if !checkIfaces {
			auditLogger.WithFields(logrus.Fields{
				"event":       "remote host validation",
				"topic":       "certificate not issued to any of local ips",
				"key":         "remote-host",
				"remote_host": certInfo.RemoteHost,
				"result":      "fail",
			}).Fatal("Certificate not authorized for local host")
			os.Exit(-1)
		}

		// Check if certificate remote user is same username trying authenticate
		if username != certInfo.RemoteUser {
			auditLogger.WithFields(logrus.Fields{
				"event":       "remote user validation",
				"topic":       "certificate not issued to username trying to authenticate",
				"key":         "remote-user",
				"remote_user": certInfo.RemoteUser,
				"result":      "fail",
			}).Fatal("Certificate not authorized for local host")
			os.Exit(-1)
		}

		// Log success
		auditLogger.WithFields(logrus.Fields{
			"event":       "auth ok",
			"topic":       "authentication succeded",
			"key":         "auth",
			"remote_user": certInfo.RemoteUser,
			"result":      "success",
		}).Info("All checks passed, user authenticating...")

		// Print user to sshd
		// https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand
		fmt.Println(certInfo.RemoteUser)
	},
}

// checkInterfaces verifies if remoteHost is containned local interfaces
func checkInterfaces(remoteHost string) bool {
	remoteIP := net.ParseIP(remoteHost)
	ifacesAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range ifacesAddrs {
		_, ifaceNetAddr, _ := net.ParseCIDR(addr.String())
		if ifaceNetAddr.Contains(remoteIP) {
			return true
		}
	}
	return false
}

// getCertInfo reveives a keyID and check on GSH API for certificate
func getCertInfo(keyID string, api string) (CertInfo, error) {

	// Setting custom HTTP client with timeouts
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: time.Second,
	}
	var netClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: netTransport,
	}

	// Get certificate from API
	resp, err := netClient.Get(api + "/certificates/" + url.QueryEscape(keyID))
	if err != nil {
		log.WithFields(logrus.Fields{
			"event":  "get certinfo",
			"topic":  "get certinfo from api",
			"key":    "certinfo",
			"result": "fail",
			"error":  err.Error(),
		}).Fatal("Failed to comunicate with api")
		return CertInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.WithFields(logrus.Fields{
			"event":      "get certinfo",
			"topic":      "get certinfo from api",
			"key":        "certinfo",
			"result":     "fail",
			"statusCode": resp.StatusCode,
		}).Fatal("Failed to retrieve certinfo from api")
		return CertInfo{}, err
	}

	// Get body
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(logrus.Fields{
			"event":  "read certinfo body",
			"topic":  "read certinfo body from api",
			"key":    "certinfo",
			"result": "fail",
			"error":  err.Error(),
		}).Fatal("Failed to retrieve certinfo from api")
		return CertInfo{}, err
	}

	// Unmarshall API response
	var certInfo CertInfo
	err = json.Unmarshal(data, &certInfo)
	if err != nil {
		log.WithFields(logrus.Fields{
			"event":  "unmarshal response",
			"topic":  "unmarshel response form api",
			"key":    "certinfo",
			"result": "fail",
			"error":  err.Error(),
		}).Fatal("Failed to unmarshal response from api")
		os.Exit(-1)
	}
	return certInfo, nil
}
