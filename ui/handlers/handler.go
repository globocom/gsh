package handlers

import (
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// AppHandler is a struct that maintains persistence of objects used in handlers
type AppHandler struct {
	config viper.Viper
	oauth2 oauth2.Config
}

// NewAppHandler return a new pointer of user struct
func NewAppHandler(config viper.Viper, oauth2 oauth2.Config) *AppHandler {
	return &AppHandler{
		config: config,
		oauth2: oauth2,
	}
}
