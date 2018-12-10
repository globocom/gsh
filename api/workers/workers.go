package workers

import (
	"fmt"

	"github.com/globocom/gsh/types"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
)

// Worker is default interface for workers
type Worker struct{}

// InitWorkers is the function thats starts workers
func InitWorkers(config viper.Viper, auditChannel *chan types.AuditRecord, logChannel *chan map[string]interface{}, stopChannel *chan bool, db *gorm.DB) {
	workers := config.GetInt("WORKERS_AUDIT")
	for j := 0; j < workers; j++ {
		worker := &Worker{}
		go worker.WriteAudit(auditChannel, stopChannel, db)
	}
	workers = config.GetInt("WORKERS_LOG")
	for j := 0; j < workers; j++ {
		worker := &Worker{}
		go worker.WriteLog(logChannel, stopChannel)
	}

}

// WriteAudit is the function thats receive AuditRecord from channel auditChannel and handle it
func (w *Worker) WriteAudit(auditChannel *chan types.AuditRecord, stopChannel *chan bool, db *gorm.DB) {
	for {
		select {
		case auditRecord := <-*auditChannel:
			db.Create(&auditRecord)
		case <-*stopChannel:
			return
		}
	}
}

// WriteLog is the function thats receive map from channel auditRecordChannel and handle it
func (w *Worker) WriteLog(logChannel *chan map[string]interface{}, stopChannel *chan bool) {
	for {
		select {
		case logRecord := <-*logChannel:
			fmt.Printf("%v\n", logRecord)
		case <-*stopChannel:
			return
		}
	}
}

// StopWorkers it is a function interrupts the workers
func StopWorkers(stopChannel *chan bool) {
	*stopChannel <- false
}
