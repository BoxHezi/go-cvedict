package services

import (
	"time"

	model "cve-dict/model"
	db "cve-dict/services/database"
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

// return: addedCves, modifiedCves, deletedCves
func DoFetch(source string) ([]model.Cve, []model.Cve, []model.Cve) {
	var addedCves, modifiedCves, deletedCves []model.Cve
	if source == "nvd" {
		addedCves, modifiedCves, deletedCves = fetchFromNvd()
	} else if source == "git" {
		addedCves, modifiedCves, deletedCves = fetchFromGit()
	}
	return addedCves, modifiedCves, deletedCves
}

// return: addedCves, modifiedCves
func DoUpdate(nvdStatus *model.NvdStatus) ([]model.Cve, []model.Cve) {
	addedCves := fetchAddedCves(nvdStatus.CveCount) // get added cves
	time.Sleep(6 * time.Second)
	historyCves := fetchCvesHistory(nvdStatus.CveHistoryCount) // get cve history

	// ignore added cves, remove duplicate cve id, get ID for modified CVEs
	modifiedIds := getModifiedIds(addedCves, historyCves)
	modifiedCves := fetchModifiedCves(modifiedIds) // fetch modified CVEs

	nvdStatus.SetCveCount(nvdStatus.CveCount + len(addedCves))
	nvdStatus.SetCveHistoryCount(nvdStatus.CveHistoryCount + len(historyCves))

	return addedCves, modifiedCves
}
