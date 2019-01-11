package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
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
		// prevent user inserted information lost
		sess.Values["user_key"] = c.FormValue("user_key")
		sess.Values["remote_host"] = c.FormValue("remote_host")

		// save session
		sess.Save(c.Request(), c.Response())

		return c.Redirect(http.StatusFound, "/auth")
	}

	// Please note the the second parameter "request.html" is the template name and should
	// be equal to one of the keys in the TemplateRegistry array defined in main.go
	return c.Render(http.StatusOK, "request.html", map[string]interface{}{
		"name":        "Generate your SSH certificate",
		"remote_user": sess.Values[h.config.GetString("AUTH_USERNAME_CLAIM")].(string),
		"user_ip":     c.RealIP(),
		"csrf":        c.Get("csrf"),
		"remote_host": sess.Values["remote_host"],
		"user_key":    sess.Values["user_key"],
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
		// prevent user inserted information lost
		sess.Values["user_key"] = c.FormValue("user_key")
		sess.Values["remote_host"] = c.FormValue("remote_host")

		// save session
		sess.Save(c.Request(), c.Response())

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

	// check username
	remoteUser := sess.Values[h.config.GetString("AUTH_USERNAME_CLAIM")].(string)
	if len(remoteUser) == 0 {
		remoteUser = c.FormValue("remote_host")
	}

	// prepare JSON to gsh api
	certRequest := types.CertRequest{
		Key:        c.FormValue("user_key"),
		RemoteHost: c.FormValue("remote_host"),
		RemoteUser: remoteUser,
		UserIP:     c.RealIP(),
	}

	// Making GSH request
	certRequestJSON, _ := json.Marshal(certRequest)
	req, err := http.NewRequest("POST", h.config.GetString("API_ENDPOINT"), bytes.NewBuffer(certRequestJSON))
	req.Header.Set("Authorization", "JWT "+sess.Values["rawIDToken"].(string))
	req.Header.Set("Content-Type", "application/json")
	resp, err := netClient.Do(req)
	if err != nil {
		return c.Render(http.StatusGatewayTimeout, "request.html", map[string]interface{}{
			"name":        "Generate your SSH certificate",
			"remote_user": remoteUser,
			"user_ip":     c.RealIP(),
			"csrf":        c.Get("csrf"),
			"remote_host": certRequest.RemoteHost,
			"user_key":    certRequest.Key,
			"error":       "GSH API error: " + err.Error(),
		})
	}

	// Read body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return c.Render(http.StatusGatewayTimeout, "request.html", map[string]interface{}{
			"name":        "Generate your SSH certificate",
			"remote_user": remoteUser,
			"user_ip":     c.RealIP(),
			"csrf":        c.Get("csrf"),
			"remote_host": certRequest.RemoteHost,
			"user_key":    certRequest.Key,
			"error":       "GSH API error: " + err.Error(),
		})
	}
	if resp.StatusCode != http.StatusOK {
		return c.Render(http.StatusGatewayTimeout, "request.html", map[string]interface{}{
			"name":        "Generate your SSH certificate",
			"remote_user": remoteUser,
			"user_ip":     c.RealIP(),
			"csrf":        c.Get("csrf"),
			"remote_host": certRequest.RemoteHost,
			"user_key":    certRequest.Key,
			"error":       "GSH API error (" + resp.Status + "): " + string(body),
		})
	}
	defer resp.Body.Close()

	// save session
	sess.Values["user_key"] = nil
	sess.Values["remote_host"] = nil
	sess.Save(c.Request(), c.Response())

	type CertResponse struct {
		Certificate string `json:"certificate"`
		Result      string `json:"result"`
	}
	certResponse := new(CertResponse)
	if err := json.Unmarshal(body, &certResponse); err != nil {
		return c.Render(http.StatusGatewayTimeout, "request.html", map[string]interface{}{
			"name":        "Generate your SSH certificate",
			"remote_user": remoteUser,
			"user_ip":     c.RealIP(),
			"csrf":        c.Get("csrf"),
			"remote_host": certRequest.RemoteHost,
			"user_key":    certRequest.Key,
			"error":       "Error parsing GSH API response: " + err.Error(),
		})
	}

	// Download file with SSH certificate
	c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("%s; filename=%q", "attachment", "ssh-cert.pub"))
	http.ServeContent(c.Response(), c.Request(), "ssh-cert.pub", time.Now(), strings.NewReader(certResponse.Certificate))
	return nil
}
