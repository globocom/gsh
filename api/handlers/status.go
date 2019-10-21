package handlers

import (
	"net/http"

	"github.com/labstack/echo"
)

// StatusLive is a method that respond WORKING and is used to verify that the application is running (live)
func StatusLive(echoContext echo.Context) error {
	return echoContext.String(http.StatusOK, "WORKING")
}

// StatusReady is a method which is used to verify that the application is able to receive data (ready)
func StatusReady(c echo.Context) error {
	return c.String(http.StatusOK, "WORKING")
}

// StatusConfig is a method that respond WORKING and is used to verify that the application is running (live)
func (h AppHandler) StatusConfig(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"oidc_base_url":      h.config.GetString("oidc_base_url"),
		"oidc_realm":         h.config.GetString("oidc_realm"),
		"oidc_audience":      h.config.GetString("oidc_audience"),
		"oidc_claim":         h.config.GetString("oidc_claim"),
		"oidc_claim_name":    h.config.GetString("oidc_claim_name"),
		"oidc_issuer":        h.config.GetString("oidc_issuer"),
		"oidc_certs":         h.config.GetString("oidc_certs"),
		"oidc_callback_port": h.config.GetString("oidc_callback_port"),
	})
}
