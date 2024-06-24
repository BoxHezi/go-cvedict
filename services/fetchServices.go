package services

import (
	"fmt"
	"time"

	model "cvedict/model"
	utils "cvedict/utils"

	nvd "cvedict/services/nvd"
)

const incremental int = 2000

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
		if len(tempCves) == 0 { // finished fetching
			go DoUpdateDatabase(dbConfig, cves, nil, nil)
			break
		}

		cves = append(cves, tempCves...)
		if len(cves)%20000 == 0 {
			go DoUpdateDatabase(dbConfig, cves, nil, nil)
			cves = nil
		}

		totalResults += len(tempCves)
		index += incremental
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
