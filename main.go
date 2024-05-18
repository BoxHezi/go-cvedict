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

// json2Cve generates a map of CVEs grouped by year from the given list of file paths.
//
// paths: a slice of strings representing file paths to JSON files containing CVE data.
// map[string][]model.Cve: a map where the keys are years and the values are slices of model.Cve structs.
func json2Cve(paths []string) map[string][]model.Cve {
	var cveMap map[string][]model.Cve = make(map[string][]model.Cve)

	// read JSON files => unmarshal into `cve` => store in `cves`
	for _, path := range paths {
		data := readJson(path)

		var cve *model.Cve = new(model.Cve)
		if err := json.Unmarshal(data, cve); err != nil {
			fmt.Printf("Unable to parse JSON file: %s\nError: %s\n", path, err)
			continue
		}
		// group cve by year
		year := cve.GetYear()
		if _, ok := cveMap[year]; !ok {
			cveMap[year] = []model.Cve{}
		}
		cveMap[year] = append(cveMap[year], *cve)
	}

	return cveMap
}

func main() {
	cveFilePaths := localCves()

	cves := json2Cve(cveFilePaths)
	var count int = 0
	for _, v := range cves {
		count += len(v)
	}
	fmt.Printf("Total: %d CVEs loaded \n", count)

	if len(cves) > 0 {
		client := db.Connect("")
		defer db.Disconnect(*client)

		// insert many
		for year, cve := range cves {
			var bDocs []interface{}
			for _, c := range cve {
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
			// TODO: make database configable through cmd line arguments
			db.InsertMany(*client, "dev3", year, bDocs)
		}
	}
}
