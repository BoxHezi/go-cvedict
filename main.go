package main

import (
	cmd "cvedict/services/cmd"
)

func main() {
	rootCmd := cmd.InitCmd()
	rootCmd.Execute()
}
