package handlers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/globocom/gsh/types"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
)

// CertificatePage is a method that render a form
func (h AppHandler) CertificatePage(c echo.Context) error {
	// check authentication info
	sess, _ := session.Get("gsh", c)
	if sess.Values["rawIDToken"] == nil {
		return c.Redirect(http.StatusFound, "/auth")
	}

	oauth2verifier := h.oauth2provider.Verifier(&oidc.Config{ClientID: h.config.GetString("AUTH_RESOURCE")})
	_, err := oauth2verifier.Verify(c.Request().Context(), sess.Values["rawIDToken"].(string))
	if err != nil {
		return c.Redirect(http.StatusFound, "/auth")
	}

	// Please note the the second parameter "request.html" is the template name and should
	// be equal to one of the keys in the TemplateRegistry array defined in main.go
	return c.Render(http.StatusOK, "request.html", map[string]interface{}{
		"name": "Certificate Request",
		"msg":  "Your form!",
	})
}

// CertificateRequest is a method that receive form data and send as JSON to gsh api
func (h AppHandler) CertificateRequest(c echo.Context) error {
	// check authentication info
	sess, _ := session.Get("gsh", c)
	if sess.Values["rawIDToken"] == nil {
		return c.Redirect(http.StatusFound, "/auth")
	}

	oauth2verifier := h.oauth2provider.Verifier(&oidc.Config{ClientID: h.config.GetString("AUTH_RESOURCE")})
	_, err := oauth2verifier.Verify(c.Request().Context(), sess.Values["rawIDToken"].(string))
	if err != nil {
		return c.Redirect(http.StatusFound, "/auth")
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

	// prepare JSON to gsh api
	certRequest := types.CertRequest{
		Key:        c.FormValue("key"),
		RemoteHost: c.FormValue("remote_host"),
		RemoteUser: sess.Values[h.config.GetString("AUTH_USERNAME_CLAIM")].(string),
		UserIP:     c.RealIP(),
	}

	// Making GSH request
	certRequestJSON, _ := json.Marshal(certRequest)
	req, err := http.NewRequest("POST", h.config.GetString("API_ENDPOINT"), bytes.NewBuffer(certRequestJSON))
	req.Header.Set("Authorization", "JWT "+sess.Values["rawIDToken"].(string))
	req.Header.Set("Content-Type", "application/json")
	resp, err := netClient.Do(req)
	if err != nil {
		return c.String(http.StatusGatewayTimeout, "GSH API error: "+err.Error())
	}

	// Read body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return c.String(http.StatusGatewayTimeout, "Body parser error: "+err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		c.String(http.StatusGatewayTimeout, "GSH error ("+resp.Status+"): "+string(body))
	}
	defer resp.Body.Close()

	return c.String(http.StatusOK, string(body))
}
