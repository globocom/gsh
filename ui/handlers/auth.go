package handlers

import (
	"net/http"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/gommon/random"
)

// Auth is a method that provides authentication flow using OpenID Connect
func (h AppHandler) Auth(c echo.Context) error {
	sess, _ := session.Get("session", c)

	// generate radom state
	state := random.String(32)
	sess.Values["state"] = state

	// save session
	sess.Save(c.Request(), c.Response())

	return c.Redirect(http.StatusFound, h.oauth2.AuthCodeURL(state))
}
