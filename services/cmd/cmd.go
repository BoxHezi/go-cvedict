package cmd

import (
	"fmt"
	"log"
	"sync"

	"github.com/spf13/cobra"

	model "cvedict/model"
	server "cvedict/server"
	services "cvedict/services"
	db "cvedict/services/database"
)

func InitCmd() *cobra.Command {
	rootCmd, rootFlags := initRootCmd()

	fetchCmd := initFetchCmd(rootFlags)
	updateCmd := initUpdateCmd(rootFlags)
	searchCmd := initSearchCmd(rootFlags)
	serverCmd := initServerCmd(rootFlags)

	rootCmd.AddCommand(fetchCmd, updateCmd, searchCmd, serverCmd)
	return rootCmd
}

func initRootCmd() (*cobra.Command, *model.RootFlag) {
	var rootFlags *model.RootFlag = new(model.RootFlag)
	rootCmd := &cobra.Command{
		Use:   "cvedict",
		Short: "CVE dict",
		Long:  "Local CVE Dictionary",
		// Run:   func(cmd *cobra.Command, args []string) {},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Testing Database Connection... - mongodb://%s:%d\n", *rootFlags.GetAddressP(), *rootFlags.GetPortP())
			client := db.Connect(db.ConstructUri(*rootFlags.GetAddressP(), *rootFlags.GetPortP()))
			defer db.Disconnect(client)

			if err := db.TestConnection(client); err != nil {
				log.Fatalf("Database connection failed: %s", err)
			}
		},
		TraverseChildren: true, // enabling duplicate flags for parent and child
	}
	rootCmd.PersistentFlags().StringVarP(rootFlags.GetAddressP(), "address", "a", "127.0.0.1", "database address")
	rootCmd.PersistentFlags().Uint32VarP(rootFlags.GetPortP(), "port", "p", 27017, "database port")
	rootCmd.PersistentFlags().StringVarP(rootFlags.GetDatabaseP(), "database", "d", "nvd", "database name")
	rootCmd.PersistentFlags().StringVarP(rootFlags.GetCollectionP(), "collection", "c", "cve", "collection name")
	rootCmd.PersistentFlags().StringVarP(rootFlags.GetNotifierUrlP(), "notifer", "n", "", "notifier url")

	// rootCmd.MarkPersistentFlagRequired("database")
	// rootCmd.MarkPersistentFlagRequired("collection")

	return rootCmd, rootFlags
}

func initFetchCmd(rootFlags *model.RootFlag) *cobra.Command {
	fetchCmd := &cobra.Command{
		Use:   "fetch",
		Short: "CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			dbConfig := model.CreateDbConfig(*rootFlags)

			sc := services.CreateServicesController(dbConfig, model.InitNvdStatus(), nil, model.CreateNotifier(*rootFlags))
			services.DoFetch(*sc)
		},
	}

	return fetchCmd
}

func initUpdateCmd(rootFlags *model.RootFlag) *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update CVE dict",

		Run: func(cmd *cobra.Command, args []string) {
			var wg sync.WaitGroup

			sc := services.CreateServicesController(model.CreateDbConfig(*rootFlags), model.InitNvdStatus(), nil, model.CreateNotifier(*rootFlags))
			addedCves, modifiedCves := services.DoUpdate(*sc)

			wg.Add(1)
			go services.DoUpdateDatabase(*sc, addedCves, modifiedCves, nil, &wg)

			wg.Wait()
		},
	}
	return updateCmd
}

func initSearchCmd(rootFlags *model.RootFlag) *cobra.Command {
	var searchFlag *model.SearchFlag = new(model.SearchFlag)
	searchCmd := &cobra.Command{
		Use:   "search",
		Short: "CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			sc := services.CreateServicesController(model.CreateDbConfig(*rootFlags), model.InitNvdStatus(), searchFlag, model.CreateNotifier(*rootFlags))
			cves := services.DoSearch(*sc)

			// fmt.Printf("CVEs: %d\n", len(cves))
			services.DoOutput(cves, *searchFlag.GetOutputPathP())
		},
	}

	// no shorthand flags for search command
	searchCmd.Flags().StringVar(searchFlag.GetIdP(), "id", "", "CVE ID")
	searchCmd.Flags().StringVar(searchFlag.GetYearP(), "year", "", "CVE Year")
	searchCmd.Flags().StringVar(searchFlag.GetDescP(), "desc", "", "CVE Description")
	searchCmd.Flags().Float32Var(searchFlag.GetCvssP(), "cvss", 0, "CVE CVSS Score")
	searchCmd.Flags().StringVar(searchFlag.GetOutputPathP(), "output", "", "CVE output path")

	return searchCmd
}

func initServerCmd(rootFlags *model.RootFlag) *cobra.Command {
	var serverFlag *model.ServerFlag = new(model.ServerFlag)
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Start server",
		Run: func(cmd *cobra.Command, args []string) {
			// dbConfig := model.CreateDbConfig(*rootFlags)
			// notifier := model.CreateNotifier(*rootFlags)
			sc := services.CreateServicesController(model.CreateDbConfig(*rootFlags), model.InitNvdStatus(), nil, model.CreateNotifier(*rootFlags))

			server.Run(*serverFlag.GetPortP(), sc)
		},
	}

	serverCmd.Flags().Uint32VarP(serverFlag.GetPortP(), "port", "p", 8080, "server port")

	return serverCmd
}
