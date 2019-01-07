package handlers

import (
	"github.com/spf13/viper"
)

// AppHandler is a struct that maintains persistence of objects used in handlers
type AppHandler struct {
	config viper.Viper
}

// NewAppHandler return a new pointer of user struct
func NewAppHandler(config viper.Viper) *AppHandler {
	return &AppHandler{
		config: config,
	}
}
