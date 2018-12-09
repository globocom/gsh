package handlers

import "github.com/globocom/gsh/types"

// AppHandler is a struct that maintains persistence of objects used in handlers
type AppHandler struct {
	auditChannel chan models.AuditRecord
	logChannel   chan map[string]interface{}
}

// NewAppHandler return a new pointer of user struct
func NewAppHandler(auditChannel chan models.AuditRecord, logChannel chan map[string]interface{}) *AppHandler {
	return &AppHandler{
		auditChannel: auditChannel,
		logChannel:   logChannel,
	}
}
