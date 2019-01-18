package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkPermissionCmd)
	checkPermissionCmd.Flags().String("key-id", "", "the key-id of the ssh certificate")
}

type CertInfo struct {
	Result     string `json:"result"`
	RemoteUser string `json:"remote_user"`
	RemoteHost string `json:"remote_host"`
}

// checkPermissionCmd represents the checkPermission command
var checkPermissionCmd = &cobra.Command{
	Use:   "check-permission",
	Short: "Check permissions from a new ssh authentication",
	Long: `
 Check permissions from a new ssh authentication, if one check fails it will deny the authentication.
 	`,
	Args: cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		keyID, err := cmd.Flags().GetString("key-id")
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(-1)
		}
		resp, err := http.Get("https://gsh-api.example.com/certificate/" + keyID)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(-1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Println("Error contacting gsh-api")
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
			fmt.Println("Failed to unsmarshal response from gsh-api")
			os.Exit(-1)
		}
		checkIfaces := checkInterfaces(certInfo.RemoteHost)
		if !checkIfaces {
			fmt.Println("Check interface error")
			os.Exit(-1)
		}
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
