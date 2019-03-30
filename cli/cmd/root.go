// Copyright © 2019 Globo.com
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package cmd

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gsh",
	Short: "gsh is a CLI to use GSH",
	Long: `
gsh is a CLI to use GSH.

GSH is an OpenID Connect-compatible authentication system
for OpenSSH servers. gshc uses certificate based authentication
on OpenSSH remote systems.`,

	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gshc/config.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directlßy.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Printf("Client error reading home folder: %s (%s)\n", home, err.Error())
			os.Exit(1)
		}

		// check if .gshc folder exists and creates if it not exists
		path := home + "/.gsh"
		if _, err := os.Stat(path); os.IsNotExist(err) {
			err := os.Mkdir(path, 0750)
			if err != nil {
				fmt.Printf("Client error creating config folder: %s (%s)\n", path, err.Error())
				os.Exit(1)
			}
			fmt.Printf("Client created config folder: %s\n", path)
		}

		// add path to viper config
		viper.AddConfigPath(path)

		// set config file name and type
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")

		// test if config file exists and creates if it not exists
		configFile := path + "/config.yaml"
		err = viper.ReadInConfig()
		if err != nil {
			f, err := os.Create(configFile)
			if err != nil {
				fmt.Printf("Client error creating config file: %s (%s)\n", configFile, err.Error())
				os.Exit(1)
			}
			err = f.Close()
			if err != nil {
				fmt.Printf("Client error closing config file: %s (%s)\n", configFile, err.Error())
				os.Exit(1)
			}
			fmt.Printf("Client create new config file: %s\n", configFile)
		}
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("Client error reading config file (%s)\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Using config file: %s\n\n", viper.ConfigFileUsed())
}
