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
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
	config.SetDefault("STORAGE_URI", "user:pass@tcp(localhost:3306)/gsh?charset=utf8&parseTime=True&multiStatements=true")
	config.SetEnvPrefix("GSH")
	config.AutomaticEnv()
	return *config
}

// Check verify configuration
func Check(config viper.Viper) error {
	var fails uint

	// Check envs
	if len(os.Getenv("PORT")) == 0 {
		fmt.Printf("Environment variable GSH_PORT not defined\n")
		fails++
	}
	if len(config.GetString("STORAGE_URI")) == 0 {
		fmt.Printf("Environment variable GSH_STORAGE_URI not defined\n")
		fails++
	}
	if config.GetBool("ca_authority.external") {
		if len(config.GetString("ca_authority.signer_url")) == 0 {
			fmt.Println("CA Authority signer_url not set in config file")
			fails++
		}
		if len(config.GetString("ca_authority.public_key_url")) == 0 {
			fmt.Println("CA Authority public_key_url not set in config file")
			fails++
		}
		if len(config.GetString("ca_authority.endpoint")) == 0 {
			fmt.Println("CA Authority endpoint not set in config file")
			fails++
		}
		if len(config.GetString("ca_authority.role_id")) == 0 {
			fmt.Println("CA Authority role_id not set in config file")
			fails++
		}
		if len(config.GetString("VAULT_SECRET_ID")) == 0 {
			fmt.Printf("Environment variable GSH_VAULT_SECRET_ID not defined\n")
			fails++
		}
	} else {
		if len(config.GetString("CA_PRIVATE_KEY")) == 0 {
			fmt.Printf("Environment variable GSH_CA_PRIVATE_KEY not defined\n")
			fails++
		}
		if len(config.GetString("CA_PUBLIC_KEY")) == 0 {
			fmt.Printf("Environment variable GSH_CA_PUBLIC_KEY not defined\n")
			fails++
		}
	}

	if fails > 0 {
		return errors.New("Configuração incorreta")
	}

	return nil
}
