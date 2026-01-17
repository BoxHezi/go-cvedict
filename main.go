package main

import (
	cmd "cvedict/services/cmd"
	"os"
)

func main() {
	rootCmd := cmd.InitCmd()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
