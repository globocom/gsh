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
		err := os.Setenv("PORT", "8080")
		if err != nil {
			fmt.Println("Error setting PORT environment variable")
		}
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
		if len(config.GetString("AUTH_REALM_URL")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_REALM_URL not defined")
			fails++
		}
		if len(config.GetString("AUTH_REDIRECT")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_REDIRECT not defined")
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
		if len(config.GetString("AUTH_USERNAME_CLAIM")) == 0 {
			fmt.Println("Environment variable GSH_AUTH_USERNAME_CLAIM not defined")
			fails++
		}
	}

	if config.GetString("SESSION_STORE") == "COOKIE" {
		if len(config.GetString("SESSION_STORE_AUTHENTICATION_SECRET")) == 0 {
			fmt.Println("Environment variable GSH_SESSION_STORE_AUTHENTICATION_SECRET not defined")
			fails++
		}
		if len(config.GetString("SESSION_STORE_ENCRYPTION_SECRET")) == 0 {
			fmt.Println("Environment variable GSH_SESSION_STORE_ENCRYPTION_SECRET not defined")
			fails++
		}
	}

	if len(config.GetString("API_ENDPOINT")) == 0 {
		fmt.Println("Environment variable GSH_API_ENDPOINT not defined")
		fails++
	}

	if fails > 0 {
		return errors.New("Configuration error")
	}

	return nil
}
