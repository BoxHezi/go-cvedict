package cmd

import (
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"

	services "cve-dict/services"
	db "cve-dict/services/database"

	model "cve-dict/model"
)

func InitCmd() (*cobra.Command, error) {
	rootCmd, rootFlags := initRootCmd()

	// test datasbase connection
	uri := db.ConstructUri(*rootFlags.GetAddressP(), *rootFlags.GetPortP())
	client := db.Connect(uri)
	defer db.Disconnect(client)
	if err := db.TestConnection(client); err != nil {
		return nil, err
	}

	updateCmd := initUpdateCmd(rootFlags)
	fetchCmd := initFetchCmd(rootFlags)

	rootCmd.AddCommand(updateCmd, fetchCmd)
	return rootCmd, nil
}

func initRootCmd() (*cobra.Command, *model.CmdFlags) {
	rootCmd := &cobra.Command{
		Use:   "cve-dict",
		Short: "CVE dict",
		Long:  "Local CVE Dictionary",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	var flags *model.CmdFlags = new(model.CmdFlags)

	rootCmd.PersistentFlags().StringVarP(flags.GetAddressP(), "address", "a", "127.0.0.1", "database host")
	rootCmd.PersistentFlags().Uint32VarP(flags.GetPortP(), "port", "p", 27001, "database port")
	rootCmd.PersistentFlags().StringVarP(flags.GetDatabaseP(), "database", "d", "", "database name")
	rootCmd.PersistentFlags().StringVarP(flags.GetCollectionP(), "collection", "c", "", "collection name")

	rootCmd.MarkFlagRequired("database")
	rootCmd.MarkFlagRequired("collection")

	rootCmd.ParseFlags(os.Args[1:]) // manually parse flags

	return rootCmd, flags
}

func initUpdateCmd(rootFlags *model.CmdFlags) *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			var nvdStatus *model.NvdStatus = new(model.NvdStatus)
			nvdStatus.LoadNvdStatus("./nvdStatus.json")

			addedCves, modefiedCves := services.DoUpdate(nvdStatus)
			services.DoUpdateDatabase(*rootFlags.GetAddressP(), *rootFlags.GetPortP(), *rootFlags.GetDatabaseP(), *rootFlags.GetCollectionP(), addedCves, modefiedCves, nil)

			nvdStatus.SaveNvdStatus("./nvdStatus.json")
		},
	}
	return updateCmd
}

func initFetchCmd(rootFlags *model.CmdFlags) *cobra.Command {
	sourceOptions := []string{"nvd", "git"}

	fetchCmd := &cobra.Command{
		Use:   "fetch",
		Short: "CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			if !slices.Contains(sourceOptions, args[0]) {
				fmt.Printf("Unknown	source: %s\n", args[0])
				fmt.Printf("Valid source options: %s\n", sourceOptions)
				return
			}

			addedCves, modifiedCves, deletedCves := services.DoFetch(args[0])
			services.DoUpdateDatabase(*rootFlags.GetAddressP(), *rootFlags.GetPortP(), *rootFlags.GetDatabaseP(), *rootFlags.GetCollectionP(), addedCves, modifiedCves, deletedCves)
		},
		Args: cobra.ExactArgs(1), // either nvd or git
	}

	return fetchCmd
}
