package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gsh-agent",
	Short: "gsh-agent is the agent responsible to control the server flow in gsh model authentication",
	Long: `
gshc-agent is the agent running on servers that authenticate with GSH.
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
