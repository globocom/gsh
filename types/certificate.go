package types

import (
	"time"

	"github.com/gofrs/uuid"
	"golang.org/x/crypto/ssh"
)

// CertRequest is the struct that represents a certificate request
type CertRequest struct {
	UID        uuid.UUID `json:"uid,omitempty" gorm:"column:uid;index:idx_uid"`
	Command    string    `json:"command,omitempty" gorm:"column:command"`
	Key        string    `json:"key,omitempty" gorm:"column:key" sql:"type:text"`
	RemoteUser string    `json:"remote_user,omitempty" gorm:"column:remote_user;index:idx_remote_user"`
	RemoteHost string    `json:"remote_host,omitempty" gorm:"column:remote_host;index:idx_remote_host"`
	UserIP     string    `json:"user_ip,omitempty" gorm:"column:user_ip;index:idx_user_ip"`

	ValidAfter     time.Time     `json:"-" gorm:"column:valid_after;index:idx_va"`
	ValidBefore    time.Time     `json:"-" gorm:"column:valid_before;index:idx_vb"`
	PublicKey      ssh.PublicKey `json:"-" sql:"-" gorm:"-" db:"-"`
	KeyFingerprint string        `json:"-" gorm:"column:key_fingerprint"`

	// CA used in certificate sign
	CAPublicKey   ssh.PublicKey `json:"-" sql:"-" gorm:"-" db:"-"`
	CAFingerprint string        `json:"-" gorm:"column:ca_fingerprint"`
	KeyID         string        `json:"-" gorm:"column:key_id"`

	//Certificate KeyID and Serial Number, after signed
	CertKeyID       string `json:"-" gorm:"column:cert_key_id"`
	SerialNumber    string `json:"-" gorm:"column:cert_serial_number"`
	CertType        string `json:"-" gorm:"column:cert_type"`
	CertFingerprint string `json:"-" gorm:"column:cert_fingerprint"`

	// Columns for database
	ID         uint       `json:"-" gorm:"primary_key"`
	CreatedAt  time.Time  `json:"-"`
	DeletedAt  *time.Time `json:"-" sql:"index"`
	ModifiedAt time.Time  `json:"-"`
}
