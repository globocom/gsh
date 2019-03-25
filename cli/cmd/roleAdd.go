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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/globocom/gsh/cli/cmd/auth"
	"github.com/globocom/gsh/cli/cmd/config"
	"github.com/globocom/gsh/types"
	"github.com/gosimple/slug"

	"github.com/spf13/cobra"
)

// roleAddCmd represents the roleAdd command
var roleAddCmd = &cobra.Command{
	Use:   "role-add [id]",
	Short: "Adds a new role",
	Long: `

Adds a new role. A role is a set of characteristics that composes a permission 
that will be assigned to a user. ID is a slug string thats identifies the role.

`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		// Get current target
		currentTarget := new(types.Target)
		currentTarget = config.GetCurrentTarget()

		// Validate if ID is slug string
		if !slug.IsSlug(args[0]) {
			fmt.Printf("Client error parsing id, it's a slug string?: (%v)\n", args[0])
			os.Exit(1)
		}

		// Get remote user
		if !cmd.Flags().Changed("remote-user") {
			fmt.Printf("Client error: remote-user can be defined (--remote-user)\n")
			os.Exit(1)
		}
		remoteUser, err := cmd.Flags().GetString("remote-user")
		if err != nil {
			fmt.Printf("Client error getting remote user: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Get user IP
		if !cmd.Flags().Changed("user-ip") {
			fmt.Printf("Client error: user-ip can be defined (--user-ip)\n")
			os.Exit(1)
		}
		userIP, err := cmd.Flags().GetString("user-ip")
		if err != nil {
			fmt.Printf("Client error getting user IP: (%s)\n", err.Error())
			os.Exit(1)
		}
		_, userIPVerified, err := net.ParseCIDR(userIP)
		if err != nil {
			fmt.Printf("Client error parsing user IP: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Get remote host
		if !cmd.Flags().Changed("remote-host") {
			fmt.Printf("Client error: remote-host can be defined (--remote-host)\n")
			os.Exit(1)
		}
		remoteHost, err := cmd.Flags().GetString("remote-host")
		if err != nil {
			fmt.Printf("Client error getting remote host: (%s)\n", err.Error())
			os.Exit(1)
		}
		_, remoteHostVerified, err := net.ParseCIDR(remoteHost)
		if err != nil {
			fmt.Printf("Client error parsing remote host: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Get action
		actions, err := cmd.Flags().GetString("actions")
		if err != nil {
			fmt.Printf("Client error getting action: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Get OIDC HTTP Client
		oauth2Token, err := auth.RecoverToken(currentTarget)
		if err != nil {
			fmt.Printf("Client error getting http client: (%s)\n", err.Error())
			os.Exit(1)
		}

		// prepare JSON to gsh api
		roleRequest := types.Role{
			ID:         args[0],
			RemoteUser: remoteUser,
			SourceIP:   userIPVerified.String(),
			TargetIP:   remoteHostVerified.String(),
			Actions:    actions,
		}

		// Marshall role to JSON
		roleRequestJSON, _ := json.Marshal(roleRequest)

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

		// Make GSH request
		req, err := http.NewRequest("POST", currentTarget.Endpoint+"/authz/roles", bytes.NewBuffer(roleRequestJSON))
		req.Header.Set("Authorization", "JWT "+oauth2Token.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := netClient.Do(req)
		if err != nil {
			fmt.Printf("Client error post role request: (%s)\n", err.Error())
			os.Exit(1)
		}

		// Read body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Client error reading role response: (%s)\n", err.Error())
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Client error checking http status response: (%v)\n", resp.StatusCode)
		}
		defer resp.Body.Close()

		// Parse role response
		type RoleResponse struct {
			Details string `json:"details"`
			Message string `json:"message"`
			Result  string `json:"result"`
		}

		roleResponse := new(RoleResponse)
		if err := json.Unmarshal(body, &roleResponse); err != nil {
			fmt.Printf("Client error parsing role response: (%s)\n", err.Error())
			os.Exit(1)
		}

		if roleResponse.Result == "fail" {
			fmt.Printf("Client error calling GSH API: (%v)\n", roleResponse)
			os.Exit(1)
		}
		fmt.Println(roleResponse.Message)
	},
}

func init() {
	rootCmd.AddCommand(roleAddCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// roleAddCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// roleAddCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	roleAddCmd.Flags().StringP("remote-user", "u", ".", "Defines username that certificate holder should impersonate on the remote system. Examples: '*' (any user), '.' (same user used at request) or 'alice' (or other string for only impersonate Alice)")
	roleAddCmd.Flags().StringP("user-ip", "s", "", "Defines source IP which will be allowed to initiate a connection to remote-host using this role")
	roleAddCmd.Flags().StringP("remote-host", "d", "", "Defines destination IP which will be able to be connected using this role")
	roleAddCmd.Flags().StringP("actions", "a", "permit-pty", "Defines a set of OpenSSH critical options which will be able to be used with this role")
}
