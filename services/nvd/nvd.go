package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	model "cve-dict/model"
)

const (
	nvdUrl        string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdHistoryUrl string = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
)

var (
	nvdReq *model.NvdRequest = model.CreateNvdRequest()
)

func readRespBody(resp *http.Response) []byte {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error when reading response body")
		log.Fatal(err)
	}
	defer resp.Body.Close()
	return body
}

// parseRespBody parses the given JSON byte slice into the provided result pointer.
//
// Parameters:
// - body: a byte slice containing the JSON data to be parsed.
// - result: a pointer to the struct that will hold the parsed data.
//
// Returns:
// - error: an error if the JSON parsing fails. or nil if there is no error
func parseRespBody[T model.NvdCvesResp | model.NvdCvesHistoryResp](body []byte, result *T) error {
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
		}
		return err
	}

	return nil
}

func FetchCves(params map[string]string) []model.Cve {
	var cves []model.Cve = []model.Cve{}
	for { // add loop to retry if error occurs
		nvdReq.Prepare(nvdUrl, params)
		resp := nvdReq.Send()

		body := readRespBody(resp)
		var bodyJson *model.NvdCvesResp = new(model.NvdCvesResp)
		err := parseRespBody(body, bodyJson)
		if err != nil {
			fmt.Printf("Try again: %s\n", nvdReq.FullReqUrl())
			continue
		}

		cves = bodyJson.UnpackCve()
		break
	}

	return cves
}

func FetchCvesHistory(params map[string]string) []model.CveChange {
	var cveChanges []model.CveChange

	nvdReq.Prepare(nvdHistoryUrl, params)
	resp := nvdReq.Send()

	body := readRespBody(resp)
	var bodyJson *model.NvdCvesHistoryResp = new(model.NvdCvesHistoryResp)
	err := parseRespBody(body, bodyJson)
	if err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
	}

	for _, c := range bodyJson.CveChanges {
		cveChanges = append(cveChanges, c.Change)
	}
	return cveChanges
}

// initialize NvdStatus
// 1. query cve endpoint to set up the number of CVEs
// 2. query cve history endpoint to set up the number of CVE history
// This should only be used after the first time query all data from nvd
func InitNvdStatus() model.NvdStatus {
	var status *model.NvdStatus = new(model.NvdStatus)

	// query cve endpoint to set up the number of CVEs
	status.SetCveCount(initNvdCveStatus())

	// query cve history endpoint to set up the number of CVE history
	status.SetCveHistoryCount(initNvdCveHistoryStatus())

	return *status
}

func initNvdCveStatus() int {
	nvdReq.Prepare(nvdUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
	resp := nvdReq.Send()

	body := readRespBody(resp)
	var bodyJson *model.NvdCvesResp = new(model.NvdCvesResp)
	err := parseRespBody(body, bodyJson)
	if err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
	}
	return bodyJson.TotalResults
}

func initNvdCveHistoryStatus() int {
	nvdReq.Prepare(nvdHistoryUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
	resp := nvdReq.Send()

	body := readRespBody(resp)
	var bodyJson *model.NvdCvesHistoryResp = new(model.NvdCvesHistoryResp)
	err := parseRespBody(body, bodyJson)
	if err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
	}
	return bodyJson.TotalResults
}
