package cmd

import (
	// "context"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"
	// "go.mongodb.org/mongo-driver/bson"

	services "cve-dict/services"
	// db "cve-dict/services/database"

	model "cve-dict/model"
)

func InitCmd() *cobra.Command {
	rootCmd, rootFlags := initRootCmd()
	updateCmd := initUpdateCmd()
	fetchCmd := initFetchCmd()

	rootCmd.AddCommand(updateCmd, fetchCmd)

	// uri := fmt.Sprintf("mongodb://%s:%d", *rootFlags.GetAddressP(), *rootFlags.GetPortP())
	// fmt.Println(uri)
	// client := db.Connect(uri)
	// defer db.Disconnect(*client)
	// fmt.Println(*client)

	// var result bson.M
	// if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Decode(&result); err != nil {
	// 	panic(err)
	// }
	// fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")

	fmt.Println("[DEBUG]", rootFlags.GetAddressP(), *rootFlags.GetAddressP())

	return rootCmd
}

func initRootCmd() (*cobra.Command, *model.CmdFlags) {
	var flags *model.CmdFlags = new(model.CmdFlags)
	rootCmd := &cobra.Command{
		Use:   "cve-dict",
		Short: "CVE dict",
		Long:  "Local CVE Dictionary",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	rootCmd.Flags().StringVarP(flags.GetAddressP(), "address", "a", "127.0.0.1", "database host")
	rootCmd.Flags().Uint32VarP(flags.GetPortP(), "port", "p", 27001, "database port")
	rootCmd.Flags().StringVarP(flags.GetDatabaseP(), "database", "d", "", "database name")
	rootCmd.Flags().StringVarP(flags.GetCollectionP(), "collection", "c", "", "collection name")

	rootCmd.ParseFlags(os.Args[1:]) // manually parse flags

	fmt.Println(*flags.GetAddressP())
	fmt.Println(*flags.GetPortP())

	// rootCmd.MarkFlagRequired("database")
	// rootCmd.MarkFlagRequired("collection")

	return rootCmd, flags
}

func initUpdateCmd() *cobra.Command {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update CVE dict",
		Run: func(cmd *cobra.Command, args []string) {
			services.DoUpdate()
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
				services.FetchFromNvd()
			} else if args[0] == "git" {
				services.FetchFromGit()
			}
		},
		Args: cobra.ExactArgs(1), // either nvd or git
	}

	return fetchCmd
}
