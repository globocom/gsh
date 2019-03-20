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

	"github.com/labstack/echo"
	"github.com/spf13/viper"
	jose "gopkg.in/square/go-jose.v2"
)

// IDToken is the struct that holds all information about a JWT token
type IDToken struct {
	Issuer            string                 `json:"iss"`
	Subject           string                 `json:"sub"`
	Audience          audience               `json:"aud"`
	AuthorizedParty   string                 `json:"azp"`
	Expiry            jsonTime               `json:"exp"`
	IssuedAt          jsonTime               `json:"iat"`
	Nonce             string                 `json:"nonce"`
	AtHash            string                 `json:"at_hash"`
	Name              string                 `json:"name"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	MiddleName        string                 `json:"middle_name"`
	Nickname          string                 `json:"nickname"`
	PhoneNumber       string                 `json:"phone_number"`
	Email             string                 `json:"email"`
	ClaimNames        map[string]string      `json:"_claim_names"`
	ClaimSources      map[string]claimSource `json:"_claim_sources"`
}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}
type jsonTime time.Time
type audience []string

// ValidateJWT validates JWT based on audience, expiration, signature and issuer and returns a valid JWT token if it succeeds
func ValidateJWT(c echo.Context, config viper.Viper) (IDToken, error) {
	var err error
	token := IDToken{}

	// Check authorizationHeader (length and content)
	// Example: Authorization: JWT <string with JWT>
	authorizationHeader := c.Request().Header.Get("Authorization")
	if len(authorizationHeader) == 0 {
		return token, errors.New("ValidateJWT: Authorization header not set")
	}
	jwtSlice := strings.Split(authorizationHeader, "JWT")
	if len(jwtSlice) != 1 {
		return token, errors.New("ValidateJWT: JWT string at authorization header not found")
	}
	jwt := jwtSlice[0]

	// Parse JWT
	token, err = parseIDToken(jwt)
	if err != nil {
		return token, fmt.Errorf("ValidateJWT: %v", err.Error())
	}

	// Verify JWT claims
	err = verifyAudience(token, config.GetString("oidc_audience"))
	if err != nil {
		return token, fmt.Errorf("ValidateJWT: %v", err.Error())
	}
	err = verifyAuthorizedParty(token, config.GetString("oidc_authorized_party"))
	if err != nil {
		return token, fmt.Errorf("ValidateJWT: %v", err.Error())
	}
	err = verifyExpiry(token)
	if err != nil {
		return token, fmt.Errorf("ValidateJWT: %v", err.Error())
	}

	// Verify signature
	keyURL := config.GetString("oidc_base_url") + "/" + config.GetString("oidc_realm") + "/protocol/openid-connect/certs"
	err = verifySignature(jwt, keyURL)
	if err != nil {
		return token, fmt.Errorf("ValidateJWT: %v", err.Error())
	}
	issuer := config.GetString("oidc_base_url") + "/" + config.GetString("oidc_realm")
	err = verifyIssuer(token, issuer)
	if err != nil {
		return token, fmt.Errorf("ValidateJWT: %v", err.Error())
	}

	return token, nil
}

func verifySignature(jwt, certsURL string) error {
	// Parse signature
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return fmt.Errorf("verifySignature: Malformed JWT signature (%v)", err)
	}

	// Get JWT keys from OICD
	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
	}
	req, _ := http.NewRequest("GET", certsURL, nil)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("verifySignature: Failed to get JWT Keys (%v)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("verifySignature: Failed to get JWT Keys, OIDC Server status code: " + string(resp.StatusCode))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("verifySignature: Unable to read response body (%v)", err)
	}
	var keySet jose.JSONWebKeySet
	err = unmarshalResp(resp, body, &keySet)
	if err != nil {
		return fmt.Errorf("verifySignature: Failed to decode keys (%v) %s", err, body)
	}

	// Test with each key (if all fails, signature is invalid)
	fails := 0
	for _, key := range keySet.Keys {
		_, err = jws.Verify(&key)
		if err != nil {
			fails++
		}
	}
	if fails == len(keySet.Keys) {
		return errors.New("verifySignature: Invalid signature")
	}

	return nil
}

func verifyExpiry(token IDToken) error {
	if time.Time(token.Expiry).Before(time.Now()) {
		return fmt.Errorf("Token is expired (%s)", time.Time(token.Expiry).String())
	}
	return nil
}

func verifyAudience(token IDToken, audience string) error {
	fail := false
	for _, aud := range token.Audience {
		if aud == audience {
			fail = true
		}
	}
	if !fail {
		return errors.New("verifyAudience: Id Token issued to other audience")
	}
	return nil
}

func verifyAuthorizedParty(token IDToken, azp string) error {
	// Verifies if authorized party is present
	if len(azp) == 0 && len(token.AuthorizedParty) == 0 {
		return nil
	}
	if token.AuthorizedParty != azp {
		return fmt.Errorf("verifyAuthorizedParty: IDToken issued to another authorized party (%s)", azp)
	}
	return nil
}

func verifyIssuer(token IDToken, issuer string) error {
	if token.Issuer != issuer {
		return fmt.Errorf("Id Token issuer not recognized")
	}
	return nil
}

func parseIDToken(jwt string) (IDToken, error) {
	var token IDToken
	parsedJwt, err := parseJWT(jwt)
	if err != nil {
		return token, fmt.Errorf("parseIDToken: Malformed jwt (%v)", err)
	}
	if err := json.Unmarshal(parsedJwt, &token); err != nil {
		return token, fmt.Errorf("parseIDToken: Failed to unmarshal claims (%v)", err)
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
		return nil, fmt.Errorf("parseJWT: Malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("parseJWT: Malformed jwt payload (%v)", err)
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
