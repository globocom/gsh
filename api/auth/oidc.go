package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/labstack/echo"
	"github.com/spf13/viper"
	jose "gopkg.in/square/go-jose.v2"
)

// Auth is interface that implements authentication strategy
type Auth interface {
	Authenticate(ctx echo.Context, config viper.Viper) (string, error)
}

// OpenIDCAuth is struct thats implements Auth interface methods for OpenID
type OpenIDCAuth struct{}

type claimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}

// jsonTime needs be a type to contain an UnmarshalJSON method as follows
type jsonTime time.Time

// Token is IDToken from OpenID Connect
type Token struct {
	Issuer            string                 `json:"iss"`
	Subject           string                 `json:"sub"`
	Audience          []string               `json:"aud"`
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

// Authenticate uses context information and configuration to authenticate an user using OpenID Connect.
//   Authenticate returns an username (or oidc_claim configured) and an error.
func (ca OpenIDCAuth) Authenticate(c echo.Context, config viper.Viper) (string, error) {
	var err error

	// Check authorizationHeader (length and content)
	// Example: Authorization: JWT <string with JWT> (note: string is second part after split)
	if c.Request() == nil {
		return "", errors.New("OpenID Authenticate: Request not set")
	}
	authorizationHeader := c.Request().Header.Get("Authorization")
	if len(authorizationHeader) == 0 {
		return "", errors.New("OpenID Authenticate: Authorization header not set")
	}
	jwtSlice := strings.Split(authorizationHeader, "JWT")
	if len(jwtSlice) != 2 {
		return "", fmt.Errorf("OpenID Authenticate: Authorization header is not at format 'Authorization: JWT <string with JWT>'")
	}
	jwt := jwtSlice[1]

	// Parse JWT
	token := Token{}
	token, err = ca.parseIDToken(jwt)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err.Error())
	}

	// Verify JWT claims
	err = ca.verifyAudience(token, config.GetString("oidc_audience"))
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err.Error())
	}
	err = ca.verifyAuthorizedParty(token, config.GetString("oidc_authorized_party"))
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err.Error())
	}
	err = ca.verifyExpiry(token)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err.Error())
	}

	err = ca.getSignatureKeys(config)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err)
	}

	// Verify signature
	err = ca.verifySignature(jwt, config)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err.Error())
	}
	issuer := config.GetString("oidc_base_url") + "/" + config.GetString("oidc_realm")
	err = ca.verifyIssuer(token, issuer)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err.Error())
	}

	field := config.GetString("oidc_claim")
	username, err := ca.getField(&token, field)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: The field declared in oidc_claim doesn't exist %v", err.Error())
	}

	return username, nil
}

func (ca OpenIDCAuth) getSignatureKeys(config viper.Viper) error {

	var keySet jose.JSONWebKeySet

	// Check if keys are defined
	keys := config.Get("oidc_keys")
	if keys != nil {
		return nil
	}

	// Get JWT keys from OICD Provider (keys are not defined at configuration)
	client := &http.Client{
		Timeout: time.Duration(10) * time.Second,
	}
	keyURL := config.GetString("oidc_base_url") + "/" + config.GetString("oidc_realm") + "/protocol/openid-connect/certs"
	req, _ := http.NewRequest("GET", keyURL, nil)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("getSignatureKeys: Failed to get JWT Keys (%v)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("getSignatureKeys: Failed to get JWT Keys, OIDC Server status code: " + string(resp.StatusCode))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("getSignatureKeys: Unable to read response body (%v)", err)
	}
	err = json.Unmarshal(body, &keySet)
	if err != nil {
		return fmt.Errorf("getSignatureKeys: Unable to parse response body (%v)", err)
	}

	config.Set("oidc_keys", keySet)

	return nil
}

func (ca OpenIDCAuth) verifySignature(jwt string, config viper.Viper) error {
	// Parse signature
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return fmt.Errorf("verifySignature: Malformed JWT signature (%v)", err)
	}

	keySet := config.Get("oidc_keys").(jose.JSONWebKeySet)

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

func (ca OpenIDCAuth) verifyExpiry(token Token) error {
	if time.Time(token.Expiry).Before(time.Now()) {
		return fmt.Errorf("Token is expired (%s)", time.Time(token.Expiry).String())
	}
	return nil
}

func (ca OpenIDCAuth) verifyAudience(token Token, audience string) error {
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

func (ca OpenIDCAuth) verifyAuthorizedParty(token Token, azp string) error {
	// Verifies if authorized party is present
	if len(azp) == 0 && len(token.AuthorizedParty) == 0 {
		return nil
	}
	if token.AuthorizedParty != azp {
		return fmt.Errorf("verifyAuthorizedParty: IDToken issued to another authorized party (%s -> %s)", azp, token.AuthorizedParty)
	}
	return nil
}

func (ca OpenIDCAuth) verifyIssuer(token Token, issuer string) error {
	if token.Issuer != issuer {
		return fmt.Errorf("Id Token issuer not recognized (expected %s -> got %s)", issuer, token.Issuer)
	}
	return nil
}

func (ca OpenIDCAuth) parseIDToken(jwt string) (Token, error) {
	var token Token
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return token, fmt.Errorf("parseIDToken: Malformed JWT, expected 3 parts got %d", len(parts))
	}
	parsedJwt, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return token, fmt.Errorf("parseIDToken: Malformed JWT payload (%v)", err)
	}

	if err := json.Unmarshal(parsedJwt, &token); err != nil {
		return token, fmt.Errorf("parseIDToken: Failed to unmarshal claims (%v)", err)
	}

	return token, nil
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

// audience needs be a type to contain an UnmarshalJSON method as follows
type audience []string

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

// getField returns the value of a field in a token or error if the field doesn't exist
func (ca OpenIDCAuth) getField(token *Token, field string) (string, error) {
	r := reflect.ValueOf(token)
	f := reflect.Indirect(r).FieldByName(field)
	result := f.String()
	if result == "<invalid Value>" {
		return "", fmt.Errorf("getField: Field (%s) not found at IDToken", field)
	}
	return result, nil
}
