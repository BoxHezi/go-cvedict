package cmd

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/spf13/cobra"

	model "cvedict/model"
	server "cvedict/server"
	services "cvedict/services"
	db "cvedict/services/database"
	utils "cvedict/utils"
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
			addedCves, modifiedCves := services.DoFetch(*dbConfig)

			notifier := model.CreateNotifier(*rootFlags)
			content := fmt.Sprintf("Fetch Operation Completed\n%s - Added: %d, Modified: %d", utils.CurrentDateTime(), len(addedCves), len(modifiedCves))
			notifier.SetContent(content)
			notifier.Send()
		},
	}

	return fetchCmd
}

func initUpdateCmd(rootFlags *model.RootFlag) *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			nvdStatus := model.InitNvdStatus()
			dbConfig := model.CreateDbConfig(*rootFlags)

			addedCves, modifiedCves := services.DoUpdate(nvdStatus)
			services.DoUpdateDatabase(*dbConfig, addedCves, modifiedCves, nil)

			go nvdStatus.SaveNvdStatus("./nvdStatus.json")

			notifier := model.CreateNotifier(*rootFlags)
			content := fmt.Sprintf("Update Operation Completed\n%s - Added: %d, Modified: %d", utils.CurrentDateTime(), len(addedCves), len(modifiedCves))
			notifier.SetContent(content)
			notifier.Send()
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
			dbConfig := model.CreateDbConfig(*rootFlags)
			cves := services.DoSearch(*dbConfig, *searchFlag.GetIdP(), *searchFlag.GetYearP(), *searchFlag.GetDescP())

			for _, c := range cves {
				s, _ := json.MarshalIndent(c, "", "\t")
				fmt.Println(string(s))
			}
		},
	}

	searchCmd.Flags().StringVar(searchFlag.GetIdP(), "id", "", "CVE ID")
	searchCmd.Flags().StringVar(searchFlag.GetYearP(), "year", "", "CVE Year")
	searchCmd.Flags().StringVar(searchFlag.GetDescP(), "desc", "", "CVE Description")

	return searchCmd
}

func initServerCmd(rootFlags *model.RootFlag) *cobra.Command {
	var serverFlag *model.ServerFlag = new(model.ServerFlag)
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Start server",
		Run: func(cmd *cobra.Command, args []string) {
			dbConfig := model.CreateDbConfig(*rootFlags)
			notifier := model.CreateNotifier(*rootFlags)

			server.Run(*serverFlag.GetPortP(), dbConfig, notifier)
		},
	}

	serverCmd.Flags().Uint32VarP(serverFlag.GetPortP(), "port", "p", 8080, "server port")

	return serverCmd
}
