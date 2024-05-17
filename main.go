package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"go.mongodb.org/mongo-driver/bson"

	db "cve-dict/database"
	"cve-dict/model"
)

func filterFiles(files []string, path string, pattern string) []string {
	var filteredFiles []string = []string{}
	if files != nil {
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
	} else if path != "" {
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
	} else if pattern == "" {
		panic("Please provide pattern")
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

// json2Cve reads JSON files from the provided paths, unmarshals them into model.Cve objects, and returns a slice of model.Cve.
//
// paths: a slice of strings representing the file paths of the JSON files to read.
// []model.Cve: a slice of model.Cve objects unmarshaled from the JSON files.
func json2Cve(paths []string) []model.Cve {
	var cves []model.Cve

	// read JSON files => unmarshal into `cve` => store in `cves`
	for _, path := range paths {
		data := readJson(path)

		var cveJson *model.Cve = new(model.Cve)
		if err := json.Unmarshal(data, cveJson); err != nil {
			fmt.Printf("Unable to parse JSON file: %s\nError: %s\n", path, err)
			continue
		}
		cves = append(cves, *cveJson)
	}

	return cves
}

func groupCveByYear(cves []model.Cve) map[string][]model.Cve {
	result := make(map[string][]model.Cve)
	for _, cve := range cves {
		year := cve.GetYear()
		if _, ok := result[year]; !ok {
			result[year] = []model.Cve{}
		}
		result[year] = append(result[year], cve)
	}
	return result
}

func main() {
	cveFilePaths := localCves()

	cves := json2Cve(cveFilePaths)
	// cves := json2Cve(nil) // DEBUG Purposes
	fmt.Printf("Total: %d CVEs loaded\n", len(cves))

	cveGroup := groupCveByYear(cves)
	// fmt.Println(len(cveGroup))

	// for k, v := range cveGroup {
	// 	fmt.Printf("%s: %d\n", k, len(v))
	// }

	if len(cveGroup) > 0 {
		client := db.Connect("")

		// insert many
		for k, v := range cveGroup {
			var bDocs []interface{}
			for _, c := range v {
				var bdoc interface{}
				bdoc, err := bson.Marshal(c)
				if err != nil {
					log.Fatal(err)
				}
				bDocs = append(bDocs, bdoc)
			}
			//! InsertMany sometime stop/pause inserting
			//! Two Errors:
			//! 1.unable to write wire message to network: write tcp [::1]:60067->[::1]:27100: write: broken pipe
			//! 2.socket was unexpectedly closed: EOF
			//! Errors disappear on 16/05/2024, keep this comment for reference
			db.InsertMany(*client, "dev1", k, bDocs)
		}
		defer db.Disconnect(*client)
	}

	// if len(cves) > 0 {
	// 	client := db.Connect("")

	// 	// insert many
	// 	var bDocs []interface{}
	// 	for _, c := range cves {
	// 		var bdoc interface{}
	// 		bdoc, err := bson.Marshal(c)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 		bDocs = append(bDocs, bdoc)
	// 	}

	//! InsertMany sometime stop/pause inserting
	//! Two Errors:
	//! 1.unable to write wire message to network: write tcp [::1]:60067->[::1]:27100: write: broken pipe
	//! 2.socket was unexpectedly closed: EOF
	//! Errors disappear on 16/05/2024, keep this comment for reference
	// 	db.InsertMany(*client, "test1", "pulled", bDocs)

	// 	defer db.Disconnect(*client)
	// }
}
