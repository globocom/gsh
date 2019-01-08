package handlers

import (
	"net/http"

	oidc "github.com/coreos/go-oidc"
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
