package services

import (
	"fmt"
	"sync"

	model "cvedict/model"
	db "cvedict/services/database"
	utils "cvedict/utils"
)

func DoUpdateDatabase(dbConfig model.DbConfig, addedCves, modifiedCves, deletedCves []model.Cve) {
	client := db.Connect(db.ConstructUri(dbConfig.DbHost, dbConfig.DbPort))
	defer db.Disconnect(client)

	if len(addedCves) > 0 {
		db.InsertMany(client, dbConfig.Database, dbConfig.Collection, addedCves)
	}

	for _, c := range modifiedCves {
		db.UpdateOne(client, dbConfig.Database, dbConfig.Collection, c.Id, c)
	}

	for _, c := range deletedCves {
		db.DeleteOne(client, dbConfig.Database, dbConfig.Collection, c.Id)
	}
}

// return: addedCves, modifiedCves
func DoFetch(dbConfig model.DbConfig) ([]model.Cve, []model.Cve) {
	addedCves, modifiedCves := fetchFromNvd(dbConfig)
	return addedCves, modifiedCves
}

// return: addedCves, modifiedCves
func DoUpdate(nvdStatus *model.NvdStatus) ([]model.Cve, []model.Cve) {
	addedCves := fetchAddedCves(nvdStatus.CveCount)            // get added cves
	historyCves := fetchCvesHistory(nvdStatus.CveHistoryCount) // get cve history

	// ignore added cves, remove duplicate cve id, get ID for modified CVEs
	modifiedIds := getModifiedIds(addedCves, historyCves)
	modifiedCves := fetchModifiedCves(modifiedIds) // fetch modified CVEs

	nvdStatus.SetCveCount(nvdStatus.CveCount + len(addedCves))
	nvdStatus.SetCveHistoryCount(nvdStatus.CveHistoryCount + len(historyCves))

	return addedCves, modifiedCves
}

func DoSearch(dbConfig model.DbConfig, searchFlag model.SearchFlag) []model.Cve {
	if searchFlag.IsEmpty() {
		utils.LogError(fmt.Errorf("no id, year or description provided"))
		return nil // return nil if there is no conditions passed in
	}

	query := prepareQuery(searchFlag)
	cves := QueryCves(dbConfig, query)

	if *searchFlag.GetCvssP() != 0 {
		// mongodb store floating point in binary format
		// comparison directly in mongodb can lead to unexpected results
		// cvss score passed in will be compared and filtered after docs retrieved from mongodb
		resultCves := []model.Cve{}
		for _, c := range cves {
			if c.FilterCvss(*searchFlag.GetCvssP()) {
				resultCves = append(resultCves, c)
			}
		}
		return resultCves
	}

	return cves
}

func DoOutput(cves []model.Cve, path string) {
	// use WaitGroup to avoid finish before files are written
	var wg sync.WaitGroup
	for _, c := range cves {
		wg.Add(1)
		go writeToOutput(c, path, &wg)
	}
	wg.Wait()
}
