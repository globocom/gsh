// Copyright © 2019 Globo.com
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"time"

	"github.com/globocom/gsh/api/handlers"
	"github.com/globocom/gsh/cli/cmd/auth"
	"github.com/globocom/gsh/cli/cmd/config"
	"github.com/globocom/gsh/cli/cmd/files"
	"github.com/globocom/gsh/types"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// hostConnectCmd represents the hostConnect command
var hostConnectCmd = &cobra.Command{
	Use:     "host-connect",
	Aliases: []string{"h", "c"},
	Short:   "Opens a remote shell inside a host, using SSH certificates",
	Long: `Opens a remote shell inside a host, using SSH certificates. You
can access a host just giving a DNS name or specifying the IP of the host.
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// Get current target
		currentTarget := config.GetCurrentTarget()

		// Keys struct for reuse
		type Keys struct {
			SSHPublicKey  string
			SSHPrivateKey string
		}
		keys := new(Keys)

		// Get flags for SSH key type
		keyType, err := cmd.Flags().GetString("key-type")
		if err != nil {
			fmt.Printf("Client error parsing key-type option: (%s)\n", err.Error())
			os.Exit(1)
		}
		switch keyType {
		// RSA Keys
		case "rsa":
			// Generate keys
			privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				fmt.Printf("Client error generating RSA keys: (%s)\n", err.Error())
				os.Exit(1)
			}
			// convert publick key to SSH format
			pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
			if err != nil {
				fmt.Printf("Client error converting RSA to SSH keys: (%s)\n", err.Error())
				os.Exit(1)
			}
			keys.SSHPublicKey = string(ssh.MarshalAuthorizedKey(pub))

			// convert RSA private key to PEM format
			privateKeyPEM := &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			}
			keys.SSHPrivateKey = string(pem.EncodeToMemory(privateKeyPEM))
		}

		// Get remote port
		port, err := cmd.Flags().GetString("port")
		if err != nil {
			fmt.Printf("Client error getting remote port: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Parse URL
		u, err := url.Parse(currentTarget.Endpoint)
		if err != nil {
			fmt.Printf("Client error parsing URL endpoint: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Get preferred outbound ip of this machine (first on target machine, after GSH API)
		conn, err := net.DialTimeout("tcp", args[0]+":"+port, time.Second)
		if err != nil {
			conn, err = net.Dial("tcp", u.Host)
			if err != nil {
				conn, err = net.Dial("tcp", u.Host+":"+u.Scheme)
				if err != nil {
					fmt.Printf("Client error connecting on endpoint: (%s)\n", err.Error())
					os.Exit(1)
				}
			}
		}
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.TCPAddr)

		// Make GSH API discovery
		configResponse, err := config.Discovery()
		if err != nil {
			fmt.Printf("GSH client discover error: %s\n", err.Error())
			os.Exit(1)
		}

		// Get OIDC HTTP Client
		oauth2Token, err := auth.RecoverToken(currentTarget)
		if err != nil {
			fmt.Printf("Client error getting http client: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Get info about user
		var username string
		if !cmd.Flags().Changed("username") {
			username, err = handlers.GetClaim(oauth2Token.AccessToken, configResponse.UsernameClaim)
			if err != nil {
				fmt.Printf("Client error getting username from token: (%s)\n", err.Error())
				os.Exit(1)
			}

			if username == "" {
				userLocal, err := user.Current()
				if err != nil {
					fmt.Printf("Client error getting username: (%s)\n", err.Error())
					os.Exit(1)
				}
				username = userLocal.Username
			}
		} else {
			username, err = cmd.Flags().GetString("username")
			if err != nil {
				fmt.Printf("Client error getting username: (%s)\n", err.Error())
				os.Exit(1)
			}
		}

		// check user ip
		sourceIP := localAddr.IP.String()
		if cmd.Flags().Changed("source") {
			sourceIP, err = cmd.Flags().GetString("source")
			if err != nil {
				fmt.Printf("Client error getting source-ip: (%s)\n", err.Error())
				os.Exit(1)
			}
		}

		// prepare JSON to gsh api
		certRequest := types.CertRequest{
			Key:        keys.SSHPublicKey,
			RemoteHost: args[0],
			RemoteUser: username,
			UserIP:     sourceIP,
		}

		// Marshall certificate to JSON
		certRequestJSON, _ := json.Marshal(certRequest)

		// Setting custom HTTP client with timeouts
		var netTransport = &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
		}
		var netClient = &http.Client{
			Timeout:   10 * time.Second,
			Transport: netTransport,
		}

		// Make GSH request
		req, err := http.NewRequest("POST", currentTarget.Endpoint+"/certificates", bytes.NewBuffer(certRequestJSON))
		if err != nil {
			fmt.Printf("Client error pre certificate request: (%s)\n", err.Error())
			os.Exit(1)
		}

		req.Header.Set("Authorization", "JWT "+oauth2Token.AccessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := netClient.Do(req)
		if err != nil {
			fmt.Printf("Client error post certificate request: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Read body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Client error reading certificate response: (%s)\n", err.Error())
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Client error checking http status response: (%d)\n\n%s\n", resp.StatusCode, body)
			os.Exit(1)
		}
		defer resp.Body.Close()

		// Parse certificate response
		type CertResponse struct {
			Certificate string `json:"certificate"`
			Result      string `json:"result"`
		}
		certResponse := new(CertResponse)
		if err := json.Unmarshal(body, &certResponse); err != nil {
			fmt.Printf("Client error parsing certificate response: (%s)\n", err.Error())
			os.Exit(1)
		}
		// certificate at certResponse.Certificate

		// Write files
		keyFile, certFile, err := files.WriteKeys(keys.SSHPrivateKey, certResponse.Certificate)
		if err != nil {
			fmt.Printf("Client error writing certificate files: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Check for dry flag
		dry, err := cmd.Flags().GetBool("dry")
		if err != nil {
			fmt.Printf("Client error parsing dry option: (%s)\n", err.Error())
			os.Exit(1)
		}
		if dry {
			// Run echoed ssh command (audited)
			// #nosec
			sh := exec.Command("echo", "ssh", "-i", keyFile, "-i", certFile, "-l", username, "-p", port, args[0])
			sh.Stdout = os.Stdout
			err = sh.Run()
			if err != nil {
				fmt.Printf("Client error running command: (%s)\n", err.Error())
				os.Exit(1)
			}
			os.Exit(0)
		}

		// Run ssh command (audited)
		// #nosec
		sh := exec.Command("ssh", "-i", keyFile, "-i", certFile, "-l", username, "-p", port, args[0])
		sh.Stdout = os.Stdout
		sh.Stdin = os.Stdin
		sh.Stderr = os.Stderr
		err = sh.Run()
		if err != nil {
			fmt.Printf("Client error running command: (%s)\n", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	},
}

func init() {
	rootCmd.AddCommand(hostConnectCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// hostConnectCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// hostConnectCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	hostConnectCmd.Flags().StringP("key-type", "t", "rsa", "Defines type of auto generated ssh key pair (rsa)")
	hostConnectCmd.Flags().StringP("username", "u", "from OIDC token", "Defines remote user to connect on remote host")
	hostConnectCmd.Flags().StringP("source", "s", "local ip address", "Defines user IP used as source to connect on remote host")
	hostConnectCmd.Flags().StringP("port", "p", "22", "Defines destination port used to connect on remote host")
	hostConnectCmd.Flags().BoolP("dry", "d", false, "Does not connect to the remote host using SSH, just prints the command to be executed")
}
