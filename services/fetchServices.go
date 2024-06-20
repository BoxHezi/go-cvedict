package services

import (
	"fmt"
	"time"

	model "cve-dict/model"
	utils "cve-dict/utils"

	cveServices "cve-dict/services/cve"
	git "cve-dict/services/git"
	nvd "cve-dict/services/nvd"
)

// json2Cve generates a map of CVEs grouped by year from the given list of file paths.
//
// paths: a slice of strings representing file paths to JSON files containing CVE data.
// map[string][]model.Cve: a map where the keys are years and the values are slices of model.Cve structs.
func json2Cve(paths []string) []model.Cve {
	var cves []model.Cve = []model.Cve{}

	// read JSON files => unmarshal into `cve` => store in `cves`
	for _, path := range paths {
		var cve *model.Cve = new(model.Cve)
		*cve = cveServices.ReadFromFile(path)
		cves = append(cves, *cve)
	}

	return cves
}

// return addedCves, modifiedCves, deletedCves
func fetchFromGit(dbConfig model.DbConfig) ([]model.Cve, []model.Cve, []model.Cve) {
	cves := git.InitLocalRepo()

	modifiedCves := json2Cve(cves[git.Modified])
	deletedCves := json2Cve(cves[git.Deleted])
	addedCves := json2Cve(cves[git.Added])

	fmt.Printf("New CVEs: %d\n", len(addedCves))
	fmt.Printf("Modified CVEs: %d\n", len(modifiedCves))
	fmt.Printf("Deleted CVEs: %d\n", len(deletedCves))

	DoUpdateDatabase(dbConfig, addedCves, modifiedCves, deletedCves)
	return addedCves, modifiedCves, deletedCves
}

// return addedCves, modifiedCves, deletedCves
// modifiedCves and deletedCves are nil
func fetchFromNvd(dbConfig model.DbConfig) ([]model.Cve, []model.Cve, []model.Cve) {
	var index int = 0
	var totalResults int = 0
	var cves []model.Cve = []model.Cve{}
	utils.LogInfo("Start Fetching CVEs from NVD...")
	start := time.Now()
	for {
		tempCves := nvd.FetchCves(map[string]string{"startIndex": fmt.Sprintf("%d", index)})
		if len(tempCves) == 0 {
			go DoUpdateDatabase(dbConfig, cves, nil, nil)
			break
		}

		cves = append(cves, tempCves...)

		if len(cves)%20000 == 0 {
			go DoUpdateDatabase(dbConfig, cves, nil, nil)
			cves = nil
		}

		totalResults += len(tempCves)
		index += 2000
	}
	utils.LogInfo("Done Fetching CVEs from NVD...")
	end := time.Now()
	totalDuration := end.Sub(start)
	fmt.Printf("Fetched %d CVEs in %v\n", totalResults, totalDuration)

	// init status for nvd query
	var nvdStatus model.NvdStatus = nvd.InitNvdStatus()
	nvdStatus.SaveNvdStatus("./nvdStatus.json")

	return cves, nil, nil
}
