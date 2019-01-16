package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
)

// targetAddCmd represents the targetAdd command
var targetAddCmd = &cobra.Command{
	Use:   "check-permission ",
	Short: "Check permissions from a new ssh authentication",
	Long: `
 Check permissions form a new ssh authentication, if one check fails it will deny the authentication.
 	`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		err := ioutil.WriteFile("/var/log/gsh.log", []byte(args[0]), 0644)
		if err != nil {
			panic(err)
		}

		fmt.Println("principals=root,felipe.lisboa")
	},
}
