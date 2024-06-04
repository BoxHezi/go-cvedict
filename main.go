package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

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
	if history {
		url := "https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId=CVE-2024-4978"
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error when sending request")
			log.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error when reading response body")
			log.Fatal(err)
		}

		var respJson model.NvdCvesHistoryResp
		if err := json.Unmarshal(body, &respJson); err != nil {
			fmt.Printf("Error when parsing response body: %s\n", err)
			if e, ok := err.(*json.SyntaxError); ok {
				fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
			}
			return
		}

		for _, c := range respJson.CveChanges {
			localCve = cveServices.ApplyUpdate(localCve, c.Change)
		}
		fmt.Println(localCve.CveSummary())
		cveServices.WriteToFile(localCve, "./change.json")

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
