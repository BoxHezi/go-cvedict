package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
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

func writeCvesToLocalJson(cves []model.Cve) {
	for _, c := range cves {
		cveServices.WriteToFile(c, "")
	}
}

func doUpdate() {
	// TODO: read nvdStatus json
	nvdStatus := model.NvdStatus{}
	nvdStatus.LoadNvdStatus("./nvdStatus.json")

	// TODO: fetch cves
	newCves := nvd.FetchCves(map[string]string{"startIndex": fmt.Sprintf("%d", nvdStatus.CveCount)})
	fmt.Printf("%d new CVEs\n", len(newCves))

	// TODO: fetch cve history
	time.Sleep(6 * time.Second)
	historyCves := nvd.FetchCvesHistory(map[string]string{"startIndex": fmt.Sprintf("%d", nvdStatus.CveHistoryCount)})
	fmt.Printf("%d CVE history\n", len(historyCves))

	// TODO: remove duplicate cve id and do incremental update
	modifiedIds := []string{}
	for _, history := range historyCves {
		contains := false
		for _, new := range newCves {
			if new.Id == history.CveId {
				contains = true
				break
			}
		}
		if !contains && !slices.Contains(modifiedIds, history.CveId) {
			modifiedIds = append(modifiedIds, history.CveId)
		}
	}

	// TODO: fetch modified CVEs
	var updateCves []model.Cve = []model.Cve{}
	for _, id := range modifiedIds {
		tempCve := nvd.FetchCves(map[string]string{"cveId": id})[0]
		updateCves = append(updateCves, tempCve)
		time.Sleep(6 * time.Second)
	}

	// TODO: insert to database
	client := db.Connect("")
	defer db.Disconnect(*client)

	if len(newCves) > 0 {
		var bDocs []interface{}
		for _, c := range newCves {
			bDocs = append(bDocs, c)
		}
		db.InsertMany(*client, "nvd", "cve", bDocs)
	}

	for _, c := range updateCves {
		db.UpdateOne(*client, "nvd", "cve", c.Id, c)
	}

	// TODO: write to file
	writeCvesToLocalJson(newCves)
	writeCvesToLocalJson(updateCves)

	// TODO: update nvdStatus
	nvdStatus.SetCveCount(nvdStatus.CveCount + len(newCves))
	nvdStatus.SetCveHistoryCount(nvdStatus.CveHistoryCount + len(historyCves))
	nvdStatus.SaveNvdStatus("./nvdStatus.json")
}

func fetchFromNvd() {
	cves := nvd.FetchCves(nil)
	writeCvesToLocalJson(cves)

	client := db.Connect("")
	defer db.Disconnect(*client)

	var bDocs []interface{}
	for _, c := range cves {
		bDocs = append(bDocs, c)
	}
	db.InsertMany(*client, "nvd", "cve", bDocs)

	// init status for nvd query
	var nvdStatus model.NvdStatus = nvd.InitNvdStatus()
	fmt.Println(nvdStatus.CveCount)
	fmt.Println(nvdStatus.CveHistoryCount)

	file, _ := os.Create("nvdStatus.json")
	defer file.Close()
	data, _ := json.Marshal(nvdStatus)
	file.Write(data)
}

func fetchFromGit() {
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

func main() {
	// implement update logic
	update := false
	if update {
		doUpdate()
		return
	}

	// add fetch data from NVD API directly
	nvdSource := false
	if nvdSource {
		fetchFromNvd()
		return
	}

	// use git repo as CVEs source
	gitSource := false
	if gitSource {
		fetchFromGit()
		return
	}
}
