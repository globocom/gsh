package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/viper"
	jose "gopkg.in/square/go-jose.v2"
)

type idToken struct {
	Issuer       string                 `json:"iss"`
	Subject      string                 `json:"sub"`
	Audience     audience               `json:"aud"`
	Expiry       jsonTime               `json:"exp"`
	IssuedAt     jsonTime               `json:"iat"`
	Nonce        string                 `json:"nonce"`
	AtHash       string                 `json:"at_hash"`
	ClaimNames   map[string]string      `json:"_claim_names"`
	ClaimSources map[string]claimSource `json:"_claim_sources"`
}
type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}
type jsonTime time.Time
type audience []string

func ValidateJwt(jwt string, config viper.Viper) error {
	var err error
	err = verifyAudience(jwt, config.GetString("oidc_conf.audience"))
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	err = verifyExpiry(jwt)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	key_url := config.GetString("oidc_conf.base_url") + "/" + config.GetString("oidc_conf.realm") + "/protocol/openid-connect/certs"
	err = verifySignature(jwt, key_url)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	issuer := config.GetString("oidc_conf.base_url") + "/" + config.GetString("oidc_conf.realm")
	err = verifyIssuer(jwt, issuer)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	return nil
}

func verifySignature(jwt, certs_url string) error {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return fmt.Errorf("Malformed jwt: %v", err)
	}
	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
	}
	req, _ := http.NewRequest("GET", certs_url, nil)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to get JWT Keys, error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("Failed to get JWT Keys, OIDC Server status code: " + string(resp.StatusCode))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Unable to read response body: %v", err)
	}
	var keySet jose.JSONWebKeySet
	err = unmarshalResp(resp, body, &keySet)
	if err != nil {
		return fmt.Errorf("Failed to decode keys: %v %s", err, body)
	}
	fails := 0
	for _, key := range keySet.Keys {
		_, err = jws.Verify(&key)
		if err != nil {
			fails++
		}
	}
	if fails == len(keySet.Keys) {
		return errors.New("Invalid signature")
	}

	return nil
}

func verifyExpiry(jwt string) error {
	token, err := ParseIdToken(jwt)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	if time.Time(token.Expiry).Before(time.Now()) {
		return fmt.Errorf("Token is expired")
	}
	return nil
}

func verifyAudience(jwt, audience string) error {
	token, err := ParseIdToken(jwt)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	if token.Audience[0] != audience {
		return fmt.Errorf("Id Token issued to other audience")
	}
	return nil
}

func verifyIssuer(jwt, issuer string) error {
	token, err := ParseIdToken(jwt)
	if err != nil {
		return fmt.Errorf(err.Error())
	}
	if token.Issuer != issuer {
		return fmt.Errorf("Id Token issuer not recognized")
	}
	return nil
}

func ParseIdToken(jwt string) (idToken, error) {
	var token idToken
	parsedJwt, err := parseJWT(jwt)
	if err != nil {
		return token, fmt.Errorf("Malformed jwt: %v", err)
	}
	if err := json.Unmarshal(parsedJwt, &token); err != nil {
		return token, fmt.Errorf("Failed to unmarshal claims: %v", err)
	}

	return token, nil
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("Malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("Malformed jwt payload: %v", err)
	}
	return payload, nil
}

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = audience(auds)
	return nil
}

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}
