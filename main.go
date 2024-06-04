package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	model "cve-dict/model"

	cveServices "cve-dict/services/cve"
	db "cve-dict/services/database"
	git "cve-dict/services/git"
	nvd "cve-dict/services/nvd"
)

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
	localCve := cveServices.GetCveById("CVE-2024-4978")
	fmt.Println(localCve.CveSummary())

	// fetch cvehistory
	// TODO: change CVE histroy logic:
	// 1. check cve history
	// 2. get cveId from repo
	// 3. query cve by id
	history := true
	var ids []string
	if history {
		cveChanges := nvd.FetchCvesHistory(map[string]string{"startIndex": "992186"})
		time.Sleep(6 * time.Second)

		for _, changes := range cveChanges {
			ids = append(ids, changes.CveId)
		}

		// query changed CVE
		for _, i := range ids {
			tempCve := nvd.FetchCves(map[string]string{"cveId": i})[0]
			cveServices.WriteToFile(tempCve, fmt.Sprintf("./%s.json", tempCve.Id))

			time.Sleep(6 * time.Second) // NVD requests 6 seconds between requests
		}

		return
	}

	// add fetch data from NVD API directly
	testNvd := false
	if testNvd {
		cves := nvd.FetchCves(nil)
		for _, cve := range cves {
			cveServices.WriteToFile(cve, "")
		}
		return
	}

	gitSource := false
	if gitSource {
		cves := git.InitLocalRepo()

		modifiedCves := json2Cve(cves[git.Modified])
		deletedCves := json2Cve(cves[git.Deleted])
		addedCves := json2Cve(cves[git.Added])

		fmt.Printf("New CVEs: %d\n", len(addedCves))
		fmt.Printf("Modified CVEs: %d\n", len(modifiedCves))
		fmt.Printf("Deleted CVEs: %d\n", len(deletedCves))

		client := db.Connect("")
		defer db.Disconnect(*client)

		// insert new CVEs
		if len(addedCves) > 0 {
			var bDocs []interface{}
			for _, c := range addedCves {
				bDocs = append(bDocs, c)
			}
			db.InsertMany(*client, "dev1", "cve", bDocs)
		}

		// update modified CVEs
		if len(modifiedCves) > 0 {
			for _, c := range modifiedCves {
				db.UpdateOne(*client, "dev1", "cve", c.Id, c)
			}
		}

		// delete deleted CVEs
		if len(deletedCves) > 0 {
			for _, c := range deletedCves {
				db.DeleteOne(*client, "dev1", "cve", c.Id)
			}
		}
	}
}
