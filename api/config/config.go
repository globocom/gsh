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
	config.SetConfigType("json")
	config.SetConfigName("config")
	config.AddConfigPath("config/")
	err := config.ReadInConfig() // Find and read the config file
	if err != nil {              // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s", err))
	}
	config.SetDefault("storage_uri", "user:pass@tcp(localhost:3306)/gsh?charset=utf8&parseTime=True&multiStatements=true")
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
	if len(config.GetString("storage_uri")) == 0 {
		fmt.Println("Storage URI (storage_uri) not set")
		fails++
	}
	if config.GetBool("ca_authority_external") {
		if len(config.GetString("ca_authority_signer_url")) == 0 {
			fmt.Println("CA authority signer URL (ca_authority_signer_url) not set")
			fails++
		}
		if len(config.GetString("ca_authority_public_key_url")) == 0 {
			fmt.Println("CA authority public key URL (ca_authority_public_key_url) not set")
			fails++
		}
		if len(config.GetString("ca_authority_endpoint")) == 0 {
			fmt.Println("CA authority endpoint (ca_authority_endpoint) not set")
			fails++
		}
		if len(config.GetString("ca_authority_role_id")) == 0 {
			fmt.Println("CA authority role ID (ca_authority_role_id) not set")
			fails++
		}
		if len(config.GetString("vault_secret_id")) == 0 {
			fmt.Println("Vault secret ID (vault_secret_id) not set")
			fails++
		}
	} else {
		if len(config.GetString("ca_private_key")) == 0 {
			fmt.Println("CA private key (ca_private_key) not set")
			fails++
		}
		if len(config.GetString("ca_public_key")) == 0 {
			fmt.Println("CA public key (ca_public_key) not set")
			fails++
		}
	}

	if fails > 0 {
		return errors.New("Incorrect configuration")
	}

	return nil
}
