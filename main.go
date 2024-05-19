package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	// "go.mongodb.org/mongo-driver/bson"

	db "cve-dict/database"
	"cve-dict/model"
)

func filterFiles(files []string, path string, pattern string) []string {
	if pattern == "" {
		panic("Please provide pattern")
	}

	var filteredFiles []string = []string{}
	if path == "" {
		// when new files are pulled
		for _, f := range files {
			match, err := filepath.Match(pattern, filepath.Base(f))
			if err != nil {
				log.Fatal(err)
			}
			if match {
				filteredFiles = append(filteredFiles, localRepoPath()+"/"+f)
			}
		}
	} else if files == nil {
		// when repo is cloned
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			match, _ := filepath.Match(pattern, filepath.Base(path))
			if match {
				filteredFiles = append(filteredFiles, path)
			}

			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
	}
	return filteredFiles
}

func readJson(path string) []byte {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	return data
}

// json2Cve generates a map of CVEs grouped by year from the given list of file paths.
//
// paths: a slice of strings representing file paths to JSON files containing CVE data.
// map[string][]model.Cve: a map where the keys are years and the values are slices of model.Cve structs.
func json2Cve(paths []string) []model.Cve {
	// var cveGroup map[string][]model.Cve = make(map[string][]model.Cve)
	var cves []model.Cve = []model.Cve{}

	// read JSON files => unmarshal into `cve` => store in `cves`
	for _, path := range paths {
		data := readJson(path)

		var cve *model.Cve = new(model.Cve)
		if err := json.Unmarshal(data, cve); err != nil {
			fmt.Printf("Unable to parse JSON file: %s\nError: %s\n", path, err)
			continue
		}
		cves = append(cves, *cve)
	}

	return cves
}

func main() {
	cveFilePaths := localCveSummary()
	// fmt.Printf("New CVEs: %d\n", len(cveFilePaths[statusAdded]))
	// fmt.Printf("Modified CVEs: %d\n", len(cveFilePaths[statusModified]))
	// fmt.Printf("Deleted CVEs: %d\n", len(cveFilePaths[statusDeleted]))

	fmt.Println("Added CVEs:")
	for _, path := range cveFilePaths[statusAdded] {
		fmt.Println(path)
	}
	fmt.Println("Modified CVEs:")
	for _, path := range cveFilePaths[statusModified] {
		fmt.Println(path)
	}
	fmt.Println("Deleted CVEs:")
	for _, path := range cveFilePaths[statusDeleted] {
		fmt.Println(path)
	}

	// TODO: 1. Modified CVE => update database
	// TODO: 2. Deleted CVE => delete from database
	// TODO: 3. Added CVE => insert to database

	// cves := json2Cve(cveFilePaths)
	// fmt.Printf("Total: %d CVEs loaded\n", len(cves))

	// if len(cves) > 0 {
	// 	client := db.Connect("")
	// 	defer db.Disconnect(*client)

	// 	var bDocs []interface{}
	// 	for _, c := range cves {
	// 		var bdoc interface{}
	// 		bdoc, err := bson.Marshal(c)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 		bDocs = append(bDocs, bdoc)
	// 	}
	// 	//! InsertMany sometime stop/pause inserting
	// 	//! Two Errors:
	// 	//! 1.unable to write wire message to network: write tcp [::1]:60067->[::1]:27100: write: broken pipe
	// 	//! 2.socket was unexpectedly closed: EOF
	// 	//! Errors disappear on 16/05/2024, keep this comment for reference
	// 	db.InsertMany(*client, "dev1", "cve", bDocs)
	// }

	db.Disconnect(*db.Connect(""))
}
