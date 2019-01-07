package config

import (
	"errors"
	"fmt"
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
	config.SetEnvPrefix("GSH")
	config.AutomaticEnv()
	return *config
}

// Check verify configuration
func Check(config viper.Viper) error {
	var fails uint

	// Check envs
	if len(os.Getenv("PORT")) == 0 {
		fmt.Printf("Environment variable PORT not defined\n")
		fails++
	}
	if len(config.GetString("AUTH_TYPE")) == 0 {
		fmt.Printf("Environment variable GSH_AUTH_TYPE not defined\n")
		fails++
	}

	if config.GetString("AUTH_TYPE") == "OPENID" {
		if len(config.GetString("AUTH_REALM")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_REALM not defined")
			fails++
		}
		if len(config.GetString("AUTH_SERVER_URL")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_SERVER_URL not defined")
			fails++
		}
		if len(config.GetString("AUTH_SSL_REQUIRED")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_SSL_REQUIRED not defined")
			fails++
		}
		if len(config.GetString("AUTH_RESOURCE")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_RESOURCE not defined")
			fails++
		}
		if len(config.GetString("AUTH_CREDENTIALS_SECRET")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_CREDENTIALS_SECRET not defined")
			fails++
		}
	}

	if fails > 0 {
		return errors.New("Configuration error")
	}

	return nil
}
