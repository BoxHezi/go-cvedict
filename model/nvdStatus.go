package model

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
)

// use NvdStatus to track the number of CVEs and CVE history
// when incremental update required, use these number as startIndex
type NvdStatus struct {
	CveCount        int `json:"cveCount"`
	CveHistoryCount int `json:"cveHistoryCount"`
}

func (n *NvdStatus) SetCveCount(count int) {
	n.CveCount = count
}

func (n *NvdStatus) SetCveHistoryCount(count int) {
	n.CveHistoryCount = count
}

func (n *NvdStatus) LoadNvdStatus(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		err = fmt.Errorf("local nvdStatus json file not found: %s", err)
		log.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(file) // read local nvdStatus json file
	if err != nil {
		log.Fatal(err)
	}

	var nvdStatus NvdStatus
	err = json.Unmarshal(data, &nvdStatus)
	if err != nil {
		log.Fatal(err)
	}

	n.SetCveCount(nvdStatus.CveCount)
	n.SetCveHistoryCount(nvdStatus.CveHistoryCount)
}
