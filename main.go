package main

import (
	"log"

	cmd "cve-dict/services/cmd"
)

func main() {
	rootCmd, err := cmd.InitCmd()
	if err != nil {
		log.Fatal(err)
	}
	rootCmd.Execute()
}
