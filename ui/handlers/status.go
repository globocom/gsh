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
	return c.String(http.StatusOK, "WORKING")
}
