package main

import (
	cmd "cve-dict/services/cmd"
)

func main() {
	rootCmd := cmd.InitCmd()
	rootCmd.Execute()
}
