package services

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

func FetchFromGit() {
	cves := git.InitLocalRepo()

	modifiedCves := json2Cve(cves[git.Modified])
	deletedCves := json2Cve(cves[git.Deleted])
	addedCves := json2Cve(cves[git.Added])

	fmt.Printf("New CVEs: %d\n", len(addedCves))
	fmt.Printf("Modified CVEs: %d\n", len(modifiedCves))
	fmt.Printf("Deleted CVEs: %d\n", len(deletedCves))

	client := db.Connect("")
	defer db.Disconnect(*client)

	if len(addedCves) > 0 {
		var bDocs []interface{}
		for _, c := range addedCves {
			bDocs = append(bDocs, c)
		}
		db.InsertMany(*client, "dev1", "cve", bDocs)
	}

	for _, c := range modifiedCves {
		db.UpdateOne(*client, "dev1", "cve", c.Id, c)
	}

	for _, c := range deletedCves {
		db.DeleteOne(*client, "dev1", "cve", c.Id)
	}
}

func FetchFromNvd() {
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
	nvdStatus.SaveNvdStatus("./nvdStatus.json")
}

func DoUpdate() {
	// read nvdStatus json
	nvdStatus := model.NvdStatus{}
	nvdStatus.LoadNvdStatus("./nvdStatus.json")

	// fetch cves
	addedCves := nvd.FetchCves(map[string]string{"startIndex": fmt.Sprintf("%d", nvdStatus.CveCount)})
	fmt.Printf("%d new CVEs\n", len(addedCves))

	// fetch cve history
	time.Sleep(6 * time.Second)
	historyCves := nvd.FetchCvesHistory(map[string]string{"startIndex": fmt.Sprintf("%d", nvdStatus.CveHistoryCount)})
	fmt.Printf("%d CVE history\n", len(historyCves))

	// remove duplicate cve id and get ID for modified CVEs
	modifiedIds := []string{}
	for _, history := range historyCves {
		contains := false
		for _, new := range addedCves {
			if new.Id == history.CveId {
				contains = true
				break
			}
		}
		if !contains && !slices.Contains(modifiedIds, history.CveId) {
			modifiedIds = append(modifiedIds, history.CveId)
		}
	}

	// fetch modified CVEs
	var modifiedCves []model.Cve = []model.Cve{}
	for _, id := range modifiedIds {
		tempCve := nvd.FetchCves(map[string]string{"cveId": id})[0]
		modifiedCves = append(modifiedCves, tempCve)
		time.Sleep(6 * time.Second)
	}

	// insert to database
	client := db.Connect("")
	defer db.Disconnect(*client)

	if len(addedCves) > 0 {
		var bDocs []interface{}
		for _, c := range addedCves {
			bDocs = append(bDocs, c)
		}
		db.InsertMany(*client, "nvd", "cve", bDocs)
	}

	for _, c := range modifiedCves {
		db.UpdateOne(*client, "nvd", "cve", c.Id, c)
	}

	// write to file
	writeCvesToLocalJson(addedCves)
	writeCvesToLocalJson(modifiedCves)

	// update nvdStatus
	nvdStatus.SetCveCount(nvdStatus.CveCount + len(addedCves))
	nvdStatus.SetCveHistoryCount(nvdStatus.CveHistoryCount + len(historyCves))
	nvdStatus.SaveNvdStatus("./nvdStatus.json")
}
