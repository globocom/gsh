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

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/99designs/keyring"
	oidc "github.com/coreos/go-oidc"
	"github.com/globocom/gsh/types"
	"github.com/labstack/gommon/random"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// Setup HTML messages
const callbackPage = `<!DOCTYPE html>
<html>
<head>
	<style>
	body {
		text-align: center;
	}
	</style>
</head>
<body>
	%s
</body>
</html>
`
const successMarkup = `
	<script>window.close();</script>
	<h1>Login Successful!</h1>
	<p>You can close this window now.</p>
`
const errorMarkup = `
	<h1>Login Failed!</h1>
	<p>%s</p>
`

// Callback is function that verifies code and get tokens (and store then on config file)
func Callback(state string, codeVerifier string, redirectURL string, oauth2config oauth2.Config, targetLabel string, finish chan bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			finish <- true
		}()
		var msg string
		var page string

		// checking state
		if state != r.URL.Query().Get("state") {
			msg = fmt.Sprintf(errorMarkup, "Invalid state")
			page = fmt.Sprintf(callbackPage, msg)
		} else {
			// State OK, continue OpenID Connect Flow
			code := r.URL.Query().Get("code")
			ctx := context.Background()
			oauth2Token, err := oauth2config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
			if err != nil {
				// Exchange error
				msg = fmt.Sprintf(errorMarkup, err.Error())
				page = fmt.Sprintf(callbackPage, msg)
			} else {
				// Exchange success
				page = fmt.Sprintf(callbackPage, successMarkup)

				// Storing tokens on current target
				StorageTokens(targetLabel, *oauth2Token)
			}
		}
		w.Header().Add("Content-Type", "text/html")
		w.Write([]byte(page))
	}
}

// PKCEgenerator returns a valid codeVerifier and codeChallenge
func PKCEgenerator() (string, string) {
	// Create a code verifier
	// https://tools.ietf.org/html/rfc7636#section-4.1
	codeVerifier := random.String(128, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321-._~")

	// Generate a code challenge
	// https://tools.ietf.org/html/rfc7636#section-4.2
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.StdEncoding.EncodeToString(h.Sum(nil))
	codeChallenge = strings.Replace(codeChallenge, "+", "-", -1)
	codeChallenge = strings.Replace(codeChallenge, "/", "_", -1)
	codeChallenge = strings.Replace(codeChallenge, "=", "", -1)

	// return both
	return codeVerifier, codeChallenge
}

// StorageTokens uses keyring to storage refresh and access tokens
func StorageTokens(targetLabel string, token oauth2.Token) error {
	var storage []keyring.BackendType
	storageConfig := viper.GetString("targets." + targetLabel + ".token-storage")
	storage = append(storage, keyring.BackendType(storageConfig))
	ring, err := keyring.Open(keyring.Config{
		AllowedBackends: storage,
		ServiceName:     "gsh",
	})
	if err != nil {
		fmt.Printf("Client error open token-storage: (%s)\n", err.Error())
		return err
	}

	oauth2TokenJSON, err := json.Marshal(token)
	if err != nil {
		fmt.Printf("Client error marshall oauth2 tokens: (%s)\n", err.Error())
		return err
	}

	err = ring.Set(keyring.Item{
		Key:  targetLabel,
		Data: oauth2TokenJSON,
	})
	if err != nil {
		fmt.Printf("Client error using storage: (%s)\n", err.Error())
		return err
	}
	return nil
}

// RecoverToken uses keyring to recover access token
func RecoverToken(currentTarget *types.Target) (*oauth2.Token, error) {
	var storage []keyring.BackendType
	storageConfig := viper.GetString("targets." + currentTarget.Label + ".token-storage")
	storage = append(storage, keyring.BackendType(storageConfig))
	ring, err := keyring.Open(keyring.Config{
		AllowedBackends: storage,
		ServiceName:     "gsh",
	})
	if err != nil {
		fmt.Printf("Client error open token-storage: (%s)\n", err.Error())
		return nil, err
	}

	tokenKeyItem, err := ring.Get(currentTarget.Label)
	if err != nil {
		fmt.Printf("Client error reading token storage: (%s)\n", err.Error())
		return nil, err
	}

	token := new(oauth2.Token)
	if err := json.Unmarshal(tokenKeyItem.Data, &token); err != nil {
		fmt.Printf("Client error unmarshal token stored: (%s)\n", err.Error())
		return nil, err
	}

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

	ctx := context.Background()
	oauth2provider, err := oidc.NewProvider(ctx, configResponse.BaseURL+"/"+configResponse.Realm)
	if err != nil {
		fmt.Printf("GSH client setting OIDC provider error: %s\n", err.Error())
		os.Exit(1)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2config := &oauth2.Config{
		ClientID: configResponse.Audience,
		Endpoint: oauth2provider.Endpoint(),
	}
	tokenRefreshed, err := oauth2config.TokenSource(ctx, token).Token()
	if err != nil {
		fmt.Printf("GSH client renew token error: %s\n", err.Error())
		os.Exit(1)
	}

	return tokenRefreshed, nil
}
