package services

import (
	"fmt"
	"sync"

	"go.mongodb.org/mongo-driver/bson"

	model "cvedict/model"
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

func DoUpdateDatabase(sc ServicesConfig, addedCves, modifiedCves, deletedCves []model.Cve, wg *sync.WaitGroup) {
	sc.doUpdateDatabase(addedCves, modifiedCves, deletedCves, wg)
}

func DoFetch(sc ServicesConfig) ([]model.Cve, []model.Cve) {
	return sc.doFetch()
}

func DoUpdate(sc ServicesConfig) ([]model.Cve, []model.Cve) {
	return sc.doUpdate()
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

func QueryCves(sc ServicesConfig, query bson.D) []model.Cve {
	return sc.doQueryCves(query)
}

func DoRenameDbCollection(sc ServicesConfig, newName string) {
	sc.doRenameDbCollection(newName)
}

func DoDropCollection(sc ServicesConfig, collection string) {
	sc.doDropCollection(collection)
}
