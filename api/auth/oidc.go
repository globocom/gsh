package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
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
	token, err := ca.parseIDToken(jwt)
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
	issuer := config.GetString("oidc_issuer")
	err = ca.verifyIssuer(token, issuer)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: %v", err.Error())
	}

	field := config.GetString("oidc_claim_name")
	username, err := ca.getField(token, field)
	if err != nil {
		return "", fmt.Errorf("OpenID Authenticate: The field declared in oidc_claim doesn't exist %v", err.Error())
	}

	jti, err := ca.getField(token, "jti")
	if err != nil {
		jti = ""
	}
	c.Set("JTI", jti)

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
	keyURL := config.GetString("oidc_certs")
	req, err := http.NewRequest("GET", keyURL, nil)
	if err != nil {
		return fmt.Errorf("getSignatureKeys: Failed to generate request (%v)", err)
	}

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

func (ca OpenIDCAuth) verifyExpiry(token map[string]interface{}) error {

	// get exp value
	tokenExp, ok := token["exp"].(float64)
	if !ok {
		return fmt.Errorf("verifyExpiry: IDToken issued without exp (%v)", token["exp"])
	}

	if time.Time(time.Unix(int64(tokenExp), 0)).Before(time.Now()) {
		return fmt.Errorf("Token is expired (%v)", tokenExp)
	}
	return nil
}

func (ca OpenIDCAuth) verifyAudience(token map[string]interface{}, audience string) error {

	// get aud value
	tokenAud, ok := token["aud"]
	if !ok {
		return errors.New("verifyAudience: IDToken issued without audience")
	}

	// check type
	var audiences []string
	tokenAudiences, ok := tokenAud.([]interface{})
	if ok {
		// is list of strings
		for _, aud := range tokenAudiences {
			audiences = append(audiences, aud.(string))
		}
	} else {
		// is string
		audString, ok := tokenAud.(string)
		if ok {
			audiences = append(audiences, audString)
		} else {
			return errors.New("verifyAudience: aud invalid type")
		}
	}

	// check auds from token
	fail := false
	for _, aud := range audiences {
		if aud == audience {
			fail = true
		}
	}
	if !fail {
		return errors.New("verifyAudience: IDToken issued to other audience")
	}
	return nil
}

func (ca OpenIDCAuth) verifyAuthorizedParty(token map[string]interface{}, azp string) error {

	// Is OPTIONAL (https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
	tokenAzp, _ := token["azp"].(string)

	// Verifies if authorized party is present
	if len(tokenAzp) == 0 {
		return nil
	}

	if tokenAzp != azp {
		return fmt.Errorf("verifyAuthorizedParty: IDToken issued to another authorized party (%s -> %s)", azp, tokenAzp)
	}
	return nil
}

func (ca OpenIDCAuth) verifyIssuer(token map[string]interface{}, issuer string) error {

	tokenIss, ok := token["iss"].(string)
	if !ok {
		return errors.New("verifyIssuer: IDToken issued without valid iss")
	}

	if tokenIss != issuer {
		return fmt.Errorf("IDToken issuer not recognized (expected %s -> got %s)", issuer, tokenIss)
	}
	return nil
}

func (ca OpenIDCAuth) parseIDToken(jwt string) (map[string]interface{}, error) {
	var token map[string]interface{}
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

// getField returns the value of a field in a token or error if the field doesn't exist
func (ca OpenIDCAuth) getField(token map[string]interface{}, field string) (string, error) {

	tokenField, ok := token[field].(string)
	if !ok {
		return "", fmt.Errorf("getField: IDToken issued without %s", field)
	}

	return tokenField, nil
}
