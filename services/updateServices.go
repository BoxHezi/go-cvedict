package services

import (
	"fmt"
	"slices"

	model "cvedict/model"
	nvd "cvedict/services/nvd"
)

func fetchAddedCves(startIndex int) []model.Cve {
	var addedCves []model.Cve = []model.Cve{}

	for {
		tempCves := nvd.FetchCves(map[string]string{"startIndex": fmt.Sprintf("%d", startIndex)})
		addedCves = append(addedCves, tempCves...)
		startIndex += len(tempCves)

		if len(tempCves) < 2000 {
			break
		}
	}

	fmt.Printf("%d new CVEs\n", len(addedCves))
	return addedCves
}

func fetchCvesHistory(startIndex int) []model.CveChange {
	var historyCves []model.CveChange = []model.CveChange{}

	for {
		tempHistoryCves := nvd.FetchCvesHistory(map[string]string{"startIndex": fmt.Sprintf("%d", startIndex)})
		historyCves = append(historyCves, tempHistoryCves...)
		startIndex += len(tempHistoryCves)

		if len(tempHistoryCves) < 5000 {
			break
		}
	}

	fmt.Printf("%d CVE history\n", len(historyCves))
	return historyCves
}

func getModifiedIds(addedCves []model.Cve, historyCves []model.CveChange) []string {
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
	return modifiedIds
}

func fetchModifiedCves(modifiedIds []string) []model.Cve {
	var modifiedCves []model.Cve = []model.Cve{}
	for _, id := range modifiedIds {
		temp := nvd.FetchCves(map[string]string{"cveId": id})[0]
		modifiedCves = append(modifiedCves, temp)
	}
	return modifiedCves
}
