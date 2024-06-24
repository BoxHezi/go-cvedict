package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	services "cvedict/services"
	db "cvedict/services/database"

	model "cvedict/model"
	server "cvedict/server"
)

func InitCmd() *cobra.Command {
	rootCmd, rootFlags := initRootCmd()

	updateCmd := initUpdateCmd(rootFlags)
	fetchCmd := initFetchCmd(rootFlags)
	serverCmd := initServerCmd(rootFlags)

	rootCmd.AddCommand(updateCmd, fetchCmd, serverCmd)
	return rootCmd
}

func initRootCmd() (*cobra.Command, *model.RootFlag) {
	var flags *model.RootFlag = new(model.RootFlag)
	rootCmd := &cobra.Command{
		Use:   "cvedict",
		Short: "CVE dict",
		Long:  "Local CVE Dictionary",
		// Run:   func(cmd *cobra.Command, args []string) {},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Testing Database Connection... - mongodb://%s:%d\n", *flags.GetAddressP(), *flags.GetPortP())
			client := db.Connect(db.ConstructUri(*flags.GetAddressP(), *flags.GetPortP()))
			defer db.Disconnect(client)

			if err := db.TestConnection(client); err != nil {
				log.Fatalf("Database connection failed: %s", err)
			}
		},
		TraverseChildren: true, // enabling duplicate flags for parent and child
	}
	rootCmd.PersistentFlags().StringVarP(flags.GetAddressP(), "address", "a", "127.0.0.1", "database address")
	rootCmd.PersistentFlags().Uint32VarP(flags.GetPortP(), "port", "p", 27017, "database port")
	rootCmd.PersistentFlags().StringVarP(flags.GetDatabaseP(), "database", "d", "", "database name")
	rootCmd.PersistentFlags().StringVarP(flags.GetCollectionP(), "collection", "c", "", "collection name")

	// TODO: notifier - discord
	rootCmd.PersistentFlags().StringVarP(flags.GetNotifierUrlP(), "notifer", "n", "", "notifier url")

	rootCmd.MarkPersistentFlagRequired("database")
	rootCmd.MarkPersistentFlagRequired("collection")

	return rootCmd, flags
}

func initUpdateCmd(rootFlags *model.RootFlag) *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			nvdStatus := model.InitNvdStatus()
			dbConfig := model.CreateDbConfig(*rootFlags)

			addedCves, modefiedCves := services.DoUpdate(nvdStatus)
			services.DoUpdateDatabase(*dbConfig, addedCves, modefiedCves, nil)

			nvdStatus.SaveNvdStatus("./nvdStatus.json")
		},
	}
	return updateCmd
}

func initFetchCmd(rootFlags *model.RootFlag) *cobra.Command {
	fetchCmd := &cobra.Command{
		Use:   "fetch",
		Short: "CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			dbConfig := model.CreateDbConfig(*rootFlags)
			services.DoFetch(*dbConfig)
		},
	}

	return fetchCmd
}

func initServerCmd(rootFlags *model.RootFlag) *cobra.Command {
	var port uint32 = 8080
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Start server",
		Run: func(cmd *cobra.Command, args []string) {
			dbConfig := model.CreateDbConfig(*rootFlags)
			server.Run(port, dbConfig)
		},
	}

	serverCmd.Flags().Uint32VarP(&port, "port", "p", 8080, "server port")

	return serverCmd
}
