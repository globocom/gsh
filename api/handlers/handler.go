package handlers

import (
	"github.com/globocom/gsh/types"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
)

// AppHandler is a struct that maintains persistence of objects used in handlers
type AppHandler struct {
	config       viper.Viper
	auditChannel chan types.AuditRecord
	logChannel   chan map[string]interface{}
	db           *gorm.DB
}

// NewAppHandler return a new pointer of user struct
func NewAppHandler(config viper.Viper, auditChannel chan types.AuditRecord, logChannel chan map[string]interface{}, db *gorm.DB) *AppHandler {
	return &AppHandler{
		config:       config,
		auditChannel: auditChannel,
		logChannel:   logChannel,
		db:           db,
	}
}
