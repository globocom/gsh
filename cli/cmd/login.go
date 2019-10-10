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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/99designs/keyring"
	"github.com/pkg/browser"

	oidc "github.com/coreos/go-oidc"
	"github.com/globocom/gsh/cli/cmd/auth"
	"github.com/globocom/gsh/cli/cmd/config"
	"github.com/globocom/gsh/types"
	"github.com/labstack/gommon/random"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Initiates a new gsh session for a user",
	Long: `

Initiates a new gsh session for a user. Since authentication uses OpenID
Connect, it will open a web browser for the user to complete the login.

All gsh actions require the user to be authenticated (except [[gsh login]],
 [[gsh version]] and [[gsh target-*]]).
	
	`,
	Run: func(cmd *cobra.Command, args []string) {

		// Get current target
		currentTarget := new(types.Target)
		currentTarget = config.GetCurrentTarget()

		// Check for set-token-storage flag
		var setStorage string
		if !cmd.Flags().Changed("set-token-storage") {
			// user not set the flag, read from config file
			setStorageCheck := viper.Get("targets." + currentTarget.Label + ".token-storage")

			// config file not set or first time using this target, forcing user to set one
			if setStorageCheck == nil {
				fmt.Printf("Client error checking available backends for token-storage %v\n", keyring.AvailableBackends())
				os.Exit(1)
			}
			setStorage = setStorageCheck.(string)
		} else {
			var err error
			setStorage, err = cmd.Flags().GetString("set-token-storage")
			if err != nil {
				fmt.Printf("Client error parsing set-token-storage option: (%s)\n", err.Error())
				os.Exit(1)
			}
			// Check if token-storage is available
			var match bool
			for _, keyringAvailable := range keyring.AvailableBackends() {
				if string(keyringAvailable) == setStorage {
					match = true
				}
			}
			if match == false {
				fmt.Printf("Client error validating set-token-storage option (%s), option available: (%v)\n", setStorage, keyring.AvailableBackends())
				os.Exit(1)
			}
		}

		// Storing tokens on current target (config file)
		viper.Set("targets."+currentTarget.Label+".token-storage", setStorage)
		err := viper.WriteConfig()
		if err != nil {
			fmt.Printf("Client error saving config with token-storage: (%s)\n", err.Error())
			os.Exit(1)
		}

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

		// Making discovery GSH request
		resp, err := netClient.Get(currentTarget.Endpoint + "/status/config")
		if err != nil {
			fmt.Printf("GSH API is down: %s (%s)\n", currentTarget.Endpoint, err.Error())
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("GSH API body response error: %s\n", err.Error())
			os.Exit(1)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("GSH API status response error: %v\n", resp.StatusCode)
			os.Exit(1)
		}
		type ConfigResponse struct {
			BaseURL  string `json:"oidc_base_url"`
			Realm    string `json:"oidc_realm"`
			Audience string `json:"oidc_audience"`
		}
		configResponse := new(ConfigResponse)
		if err := json.Unmarshal(body, &configResponse); err != nil {
			fmt.Printf("GSH API body unmarshal error: %s\n", err.Error())
			os.Exit(1)
		}

		// Configure an OpenID Connect aware OAuth2 client.
		ctx := context.Background()
		oauth2provider, err := oidc.NewProvider(ctx, configResponse.BaseURL+"/"+configResponse.Realm)
		if err != nil {
			fmt.Printf("GSH client setting OIDC provider error: %s\n", err.Error())
			os.Exit(1)
		}

		// Setup localserver with random port
		finish := make(chan bool)
		l, err := net.Listen("tcp", "127.0.0.1:")
		if err != nil {
			fmt.Printf("GSH client cannot start localhost server: %s\n", err.Error())
			os.Exit(1)
		}
		// Get random port on localserver
		_, port, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			fmt.Printf("GSH client cannot get localhost port: %s\n", err.Error())
			os.Exit(1)
		}
		redirectURL := fmt.Sprintf("http://localhost:%s", port)

		oauth2config := oauth2.Config{
			ClientID:    configResponse.Audience,
			RedirectURL: redirectURL,
			Endpoint:    oauth2provider.Endpoint(),
			Scopes:      []string{oidc.ScopeOpenID},
		}

		// Generate radom state and PKCE codes
		state := random.String(32)
		codeVerifier, codeChallenge, err := auth.PKCEgenerator()
		if err != nil {
			fmt.Printf("GSH client cannot generate PKCE challenge: %s\n", err.Error())
			os.Exit(1)
		}

		// Generate AuthCode URL with PKCE
		authURL := oauth2config.AuthCodeURL(state, oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))

		// Setup local web server
		http.HandleFunc("/", auth.Callback(state, codeVerifier, redirectURL, oauth2config, currentTarget.Label, finish))
		server := &http.Server{}
		go server.Serve(l)

		// Open client browser to user login on OIDC
		err = browser.OpenURL(authURL)
		if err != nil {
			fmt.Println("Failed to start your browser.")
			fmt.Printf("Please open the following URL in your browser: %s\n", authURL)
		}

		// Stop local web server
		<-finish
		fmt.Println("Successfully logged in!")
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	loginCmd.Flags().StringP("set-token-storage", "s", "keychain", "Define where OIDC tokens will be stored [keychain,kwallet,wincred,secret-service,file]")
}
