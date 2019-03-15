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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/globocom/gsh/types"
	"github.com/spf13/viper"
)

// DiscoveryResponse is struct with discovery data from GSH API
type DiscoveryResponse struct {
	BaseURL       string `json:"oidc_base_url"`
	Realm         string `json:"oidc_realm"`
	Audience      string `json:"oidc_audience"`
	UsernameClaim string `json:"oidc_username_claim"`
}

// GetCurrentTarget return a types.Target with current target
func GetCurrentTarget() *types.Target {
	// Get current target
	currentTarget := new(types.Target)
	targets := viper.GetStringMap("targets")
	for k, v := range targets {
		target := v.(map[string]interface{})

		if target["current"] != nil {
			// format output for activated target
			if target["current"].(bool) {
				currentTarget.Label = k
				currentTarget.Endpoint = target["endpoint"].(string)
				currentTarget.TokenStorage = target["token-storage"].(string)
			}
		}
	}
	return currentTarget
}

// Discovery makes GET /status/config request to GSH API to get OIDC configuration
func Discovery() (*DiscoveryResponse, error) {
	// Get current target
	currentTarget := new(types.Target)
	currentTarget = GetCurrentTarget()

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
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("GSH API body response error: %s\n", err.Error())
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("GSH API status response error: %v\n", resp.StatusCode)
		return nil, err
	}
	configResponse := new(DiscoveryResponse)
	if err := json.Unmarshal(body, &configResponse); err != nil {
		fmt.Printf("GSH API body unmarshal error: %s\n", err.Error())
		return nil, err
	}
	return configResponse, nil
}
