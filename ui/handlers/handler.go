package handlers

import (
	oidc "github.com/coreos/go-oidc"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// AppHandler is a struct that maintains persistence of objects used in handlers
type AppHandler struct {
	config         viper.Viper
	oauth2config   oauth2.Config
	oauth2provider oidc.Provider
}

// NewAppHandler return a new pointer of user struct
func NewAppHandler(config viper.Viper, oauth2config oauth2.Config, oauth2provider oidc.Provider) *AppHandler {
	return &AppHandler{
		config:         config,
		oauth2config:   oauth2config,
		oauth2provider: oauth2provider,
	}
}
