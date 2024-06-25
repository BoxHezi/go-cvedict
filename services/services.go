package services

import (
	"time"

	model "cvedict/model"
	db "cvedict/services/database"

	"go.mongodb.org/mongo-driver/bson"
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

func DoSearch(dbConfig model.DbConfig, id, year, desc string) []model.Cve {
	if id == "" && year == "" && desc == "" {
		return nil
	}

	var query bson.D = bson.D{}
	if id != "" {
		query = append(query, prepareConditionFromId(id))
	}
	if year != "" {
		query = append(query, prepareConditionFromYear(year))
	}
	if desc != "" {
		query = append(query, prepareConditionFromDesc(desc))
	}

	cves := QueryCves(dbConfig, query)
	return cves
}
