package cmd

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	// services "cve-dict/services"
)

func InitCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "cve-dict",
		Short: "CVE dict",
		Long:  "Local CVE Dictionary",
	}

	updateCmd := initUpdateCmd()
	fetchCmd := initFetchCmd()

	rootCmd.AddCommand(updateCmd, fetchCmd)

	return rootCmd
}

func initUpdateCmd() *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Update")
			// services.DoUpdate()
		},
	}
	return updateCmd
}

func initFetchCmd() *cobra.Command {
	sourceOptions := []string{"nvd", "git"}

	fetchCmd := &cobra.Command{
		Use:   "fetch",
		Short: "CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			if !slices.Contains(sourceOptions, args[0]) {
				fmt.Printf("Unknown	source: %s\n", args[0])
				fmt.Printf("Valid source options: %s\n", sourceOptions)
			} else if args[0] == "nvd" {
				fmt.Println("Start fetching from NVD...")
				// services.FetchFromNvd()
			} else if args[0] == "git" {
				fmt.Println("Start fetching from Git...")
				// services.FetchFromGit()
			}
		},
		Args: cobra.ExactArgs(1),
	}

	return fetchCmd
}
