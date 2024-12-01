package services

import (
	"fmt"
	"sync"

	model "cvedict/model"
	db "cvedict/services/database"
	utils "cvedict/utils"
)

type ServicesConfig struct {
	dbConfig   *model.DbConfig
	nvdStatus  *model.NvdStatus
	searchFlag *model.SearchFlag
	notifier   *model.Notifier
}

func CreateServicesController(dbConfig *model.DbConfig, nvdStatus *model.NvdStatus, searchFlag *model.SearchFlag, notifier *model.Notifier) *ServicesConfig {
	sc := new(ServicesConfig)
	sc.dbConfig = dbConfig
	sc.nvdStatus = nvdStatus
	sc.searchFlag = searchFlag
	sc.notifier = notifier
	return sc
}

func (sc ServicesConfig) doUpdateDatabase(addCves, modifiedCves, deletedCves []model.Cve, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	client := db.Connect(db.ConstructUri(sc.dbConfig.DbHost, sc.dbConfig.DbPort))
	defer db.Disconnect(client)

	if len(addCves) > 0 {
		db.InsertMany(client, sc.dbConfig.Database, sc.dbConfig.Collection, addCves)
	}

	for _, c := range modifiedCves {
		db.UpdateOne(client, sc.dbConfig.Database, sc.dbConfig.Collection, c.Id, c)
	}

	for _, c := range deletedCves {
		db.DeleteOne(client, sc.dbConfig.Database, sc.dbConfig.Collection, c.Id)
	}
}

func DoUpdateDatabase(sc ServicesConfig, addedCves, modifiedCves, deletedCves []model.Cve, wg *sync.WaitGroup) {
	sc.doUpdateDatabase(addedCves, modifiedCves, deletedCves, wg)
}

// return: addedCves, modifiedCves
func (sc ServicesConfig) doFetch() ([]model.Cve, []model.Cve) {
	addedCves, modifiedCves := fetchFromNvd(sc)
	return addedCves, modifiedCves
}

func DoFetch(sc ServicesConfig) ([]model.Cve, []model.Cve) {
	return sc.doFetch()
}

// return: addedCves, modifiedCves
func (sc ServicesConfig) doUpdate() ([]model.Cve, []model.Cve) {
	addedCves := fetchAddedCves(sc.nvdStatus.CveCount) // get added cves
	historyCves := fetchCvesHistory(sc.nvdStatus.CveHistoryCount)

	// ignore added cves, remove duplicate cve id, get ID for modified CVEs
	modifiedIds := getModifiedIds(addedCves, historyCves)
	modifiedCves := fetchModifiedCves(modifiedIds) // fetch modified CVEs

	sc.nvdStatus.SetCveCount(sc.nvdStatus.CveCount + len(addedCves))
	sc.nvdStatus.SetCveHistoryCount(sc.nvdStatus.CveHistoryCount + len(historyCves))

	content := fmt.Sprintf("Update Operation Completed\n%s - Added: %d, Modified: %d", utils.CurrentDateTime(), len(addedCves), len(modifiedCves))
	DoSendNotification(sc, content)
	sc.nvdStatus.SaveStatus("./nvdStatus.json", nil)
	return addedCves, modifiedCves
}

func DoUpdate(sc ServicesConfig) ([]model.Cve, []model.Cve) {
	return sc.doUpdate()
}

func (sc ServicesConfig) doSearch() []model.Cve {
	query := prepareQuery(*sc.searchFlag)
	cves := QueryCves(sc, query)

	if *sc.searchFlag.GetCvssP() != 0 {
		// mongodb store floating point in binary format
		// comparison directly in mongodb can lead to unexpected results
		// cvss score passed in will be compared and filtered after docs retrieved from mongodb
		resultCves := []model.Cve{}
		for _, c := range cves {
			if c.FilterCvss(*sc.searchFlag.GetCvssP()) {
				resultCves = append(resultCves, c)
			}
		}
		return resultCves
	}

	return cves
}

func DoSearch(sc ServicesConfig) []model.Cve {
	if sc.searchFlag.IsEmpty() {
		utils.LogError(fmt.Errorf("no id, year or description provided"))
		return nil // return nil if there is no conditions passed in
	}

	return sc.doSearch()
}

func (sc ServicesConfig) doSendNotification(content string) {
	sc.notifier.SetContent(content)
	sc.notifier.Send()
}

func DoSendNotification(sc ServicesConfig, content string) {
	if sc.notifier != nil {
		sc.doSendNotification(content)
	}
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

func (sc ServicesConfig) doRenameDbCollection() {
	client := db.Connect(db.ConstructUri(sc.dbConfig.DbHost, sc.dbConfig.DbPort))
	defer db.Disconnect(client)

	db.RenameCollection(client, sc.dbConfig.Database, sc.dbConfig.Collection)
}

func DoRenameDbCollection(sc ServicesConfig) {
	sc.doRenameDbCollection()
}
