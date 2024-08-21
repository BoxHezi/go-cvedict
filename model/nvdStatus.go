package model

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"cvedict/utils"
)

// use NvdStatus to track the number of CVEs and CVE history
// when incremental update required, use these number as startIndex
type NvdStatus struct {
	CveCount        int `json:"cveCount"`
	CveHistoryCount int `json:"cveHistoryCount"`
}

func InitNvdStatus() *NvdStatus {
	nvdStatus := new(NvdStatus)
	err := nvdStatus.LoadStatus("./nvdStatus.json")
	if err != nil {
		utils.LogError(err)
		return nil
	}
	return nvdStatus
}

func (n *NvdStatus) SetCveCount(count int) {
	n.CveCount = count
}

func (n *NvdStatus) SetCveHistoryCount(count int) {
	n.CveHistoryCount = count
}

func (n *NvdStatus) LoadStatus(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		err = fmt.Errorf("local nvdStatus json file not found: %s", err)
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file) // read local nvdStatus json file
	if err != nil {
		return nil
	}

	var nvdStatus NvdStatus
	err = json.Unmarshal(data, &nvdStatus)
	if err != nil {
		return nil
	}

	n.SetCveCount(nvdStatus.CveCount)
	n.SetCveHistoryCount(nvdStatus.CveHistoryCount)

	return nil
}

func (n *NvdStatus) SaveStatus(filename string, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := json.Marshal(n)
	if err != nil {
		log.Fatal(err)
	}

	file.Write(data)
}
