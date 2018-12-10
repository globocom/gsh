package storage

import (
	"errors"
	"log"
	"time"

	"github.com/globocom/gsh/types"
	"github.com/jinzhu/gorm"

	// importing mysql
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/spf13/viper"
)

// Init prepare storage driver
func Init(config viper.Viper) (*gorm.DB, error) {

	// Configure for MYSQL using gorm
	if config.GetString("STORAGE_DRIVER") == "MYSQL" {
		// Connecting to the Database
		db, err := gorm.Open("mysql", config.GetString("STORAGE_URI"))
		if err != nil {
			log.Println(err)
		}
		// Trying to reconnect without database until maxAttempts
		var dbError error
		maxAttempts := config.GetInt("STORAGE_MAX_ATTEMPTS")
		for attempts := 1; attempts <= maxAttempts; attempts++ {
			dbError = db.DB().Ping()
			if dbError == nil {
				break
			}
			log.Println(dbError)
			time.Sleep(time.Duration(attempts) * time.Second)
		}
		if dbError != nil {
			log.Fatal(dbError)
		}
		// disabling NO_ZERO_DATE mode
		db.DB().Exec("SET SESSION sql_mode = 'ONLY_FULL_GROUP_BY,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION';")
		db.DB().SetMaxOpenConns(config.GetInt("STORAGE_MAX_CONNECTIONS"))
		db.AutoMigrate(
			&types.AuditRecord{},
			&types.CertRequest{},
		)
		if config.GetBool("STORAGE_DEBUG") {
			db.LogMode(true)
		}
		return db, nil
	}

	return nil, errors.New("Storage driver not fount")
}
