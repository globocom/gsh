package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkPermissionCmd)
	checkPermissionCmd.Flags().String("key-id", "", "the key-id of the ssh certificate")
	checkPermissionCmd.Flags().String("username", "", "the username of the user trying to authenticate")
}

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
		file, err := os.OpenFile("/var/log/gsh-audit.log", os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			log.Out = file
		} else {
			log.Info("Failed to log to file, using default stdout")
		}
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
		//defining default field to log
		auditLogger := log.WithFields(logrus.Fields{"key_id": keyID, "username": username})
		certInfo := getCertInfo(keyID)
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
		auditLogger.WithFields(logrus.Fields{
			"event":       "auth ok",
			"topic":       "authentication succeded",
			"key":         "auth",
			"remote_user": certInfo.RemoteUser,
			"result":      "success",
		}).Info("All checks passed, user authenticating...")
		fmt.Println(certInfo.RemoteUser)
	},
}

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

func getCertInfo(keyID string) CertInfo {
	resp, err := http.Get("https://gsh-api.example.com/certificate/" + keyID)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.WithFields(logrus.Fields{
			"event":  "get certinfo",
			"topic":  "get certinfo from api",
			"key":    "certinfo",
			"result": "fail",
		}).Fatal("Failed to retrieve certinfo from api")
		os.Exit(-1)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	var certInfo CertInfo
	err = json.Unmarshal(data, &certInfo)
	if err != nil {
		log.WithFields(logrus.Fields{
			"event":  "unmarshal response",
			"topic":  "unmarshel response form api",
			"key":    "certinfo",
			"result": "fail",
		}).Fatal("Failed to unmarshal response from api")
		os.Exit(-1)
	}
	return certInfo
}
