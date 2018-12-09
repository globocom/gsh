package models

import (
	"time"

	"github.com/gofrs/uuid"
)

// AuditRecord is the struct that represents AuditRecord event
type AuditRecord struct {
	UID        uuid.UUID `gorm:"column:uid;index:idx_ar_uid" json:"uid,omitempty"`
	StartTime  time.Time
	EndTime    time.Time
	Kind       string    `gorm:"index:idx_ar_kind_targetid,idx_ar_kind_targetuid"`
	TargetID   uint      `gorm:"index:idx_ar_kind_targetid"`
	TargetUID  uuid.UUID `gorm:"column:target_uid;index:idx_ar_kind_targetuid"`
	Owner      string    `gorm:"index:idx_ar_owner"`
	JTI        string
	Error      string
	Log        string
	CancelInfo string
	Cancelable bool
	Running    bool
}

// Change is the structure that keeps the modifications made and the original values
type Change struct {
	Field  string
	Before interface{}
	After  interface{}
}
