package handlers

import (
	"github.com/globocom/gsh/types"
	"github.com/spf13/viper"
)

// AppHandler is a struct that maintains persistence of objects used in handlers
type AppHandler struct {
	config       viper.Viper
	auditChannel chan models.AuditRecord
	logChannel   chan map[string]interface{}
}

// NewAppHandler return a new pointer of user struct
func NewAppHandler(config viper.Viper, auditChannel chan models.AuditRecord, logChannel chan map[string]interface{}) *AppHandler {
	return &AppHandler{
		config:       config,
		auditChannel: auditChannel,
		logChannel:   logChannel,
	}
}
