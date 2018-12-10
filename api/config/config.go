package config

import (
	"errors"
	"os"

	"github.com/spf13/viper"
)

// Init configure and check environment configuration
func Init() viper.Viper {
	// Configure defaults
	if len(os.Getenv("PORT")) == 0 {
		os.Setenv("PORT", "8000")
	}
	config := viper.New()
	config.SetDefault("CHANNEL_SIZE", 100)
	config.SetDefault("WORKERS_AUDIT", 1)
	config.SetDefault("WORKERS_LOG", 1)
	config.SetDefault("CERT_DURATION", 600000000000) // 600 secs
	config.SetDefault("STORAGE_DRIVER", "MYSQL")
	config.SetDefault("STORAGE_URI", "user:pass@tcp(localhost:3306)/gsh?charset=utf8&parseTime=True&multiStatements=true")
	config.SetDefault("STORAGE_MAX_ATTEMPTS", 20)
	config.SetDefault("STORAGE_MAX_CONNECTIONS", 20)
	config.SetDefault("STORAGE_DEBUG", false)
	config.SetEnvPrefix("GSH")
	config.AutomaticEnv()
	return *config
}

// Check verify configuration
func Check(config viper.Viper) error {
	var fails uint

	// Check envs
	if len(os.Getenv("PORT")) == 0 {
		fails++
	}
	if config.GetInt("CHANNEL_SIZE") == 0 {
		fails++
	}
	if config.GetInt("WORKERS_AUDIT") == 0 {
		fails++
	}
	if config.GetInt("WORKERS_LOG") == 0 {
		fails++
	}
	if config.GetInt("CERT_DURATION") == 0 {
		fails++
	}
	if len(config.GetString("CA_PRIVATE_KEY")) == 0 {
		fails++
	}
	if len(config.GetString("CA_PUBLIC_KEY")) == 0 {
		fails++
	}
	if len(config.GetString("STORAGE_DRIVER")) == 0 {
		fails++
	}
	if len(config.GetString("STORAGE_URI")) == 0 {
		fails++
	}

	if fails > 0 {
		return errors.New("Configuração incorreta")
	}

	return nil
}
