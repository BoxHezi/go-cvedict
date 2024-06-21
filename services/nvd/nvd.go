package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	model "cve-dict/model"
	utils "cve-dict/utils"
)

const (
	nvdUrl        string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdHistoryUrl string = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

	errSendRequest string = "error when sending request"
	errReadBody    string = "error when reading response body"
	errParseBody   string = "error when parsing response body"
)

var (
	nvdReq *model.NvdRequest = model.CreateNvdRequest()
)

func readRespBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return body, nil
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
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Body: %v\n", string(body))
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
		resp, err := nvdReq.Send()
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errSendRequest, err))
			continue
		}

		body, err := readRespBody(resp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errReadBody, err))
			continue
		}

		var nvdCveResp *model.NvdCvesResp = new(model.NvdCvesResp)
		err = parseRespBody(body, nvdCveResp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errParseBody, err))
			continue
		}

		cves = nvdCveResp.UnpackCve()
		break
	}

	return cves
}

func FetchCvesHistory(params map[string]string) []model.CveChange {
	var cveChanges []model.CveChange
	for {
		nvdReq.Prepare(nvdHistoryUrl, params)
		resp, err := nvdReq.Send()
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errSendRequest, err))
			continue
		}

		body, err := readRespBody(resp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errReadBody, err))
			continue
		}

		var nvdCvesHistoryResp *model.NvdCvesHistoryResp = new(model.NvdCvesHistoryResp)
		err = parseRespBody(body, nvdCvesHistoryResp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errParseBody, err))
			continue
		}

		cveChanges = nvdCvesHistoryResp.UnpackCveChange()
		break
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
	var totalResults int = 0
	for {
		nvdReq.Prepare(nvdUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
		resp, err := nvdReq.Send()
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errSendRequest, err))
			continue
		}

		body, err := readRespBody(resp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errReadBody, err))
			continue
		}

		var nvdCveResp *model.NvdCvesResp = new(model.NvdCvesResp)
		err = parseRespBody(body, nvdCveResp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errParseBody, err))
			continue
		}

		totalResults = nvdCveResp.TotalResults
		break
	}
	return totalResults
}

func initNvdCveHistoryStatus() int {
	var totalResults int = 0
	for {
		nvdReq.Prepare(nvdHistoryUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
		resp, err := nvdReq.Send()
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errSendRequest, err))
			continue
		}

		body, err := readRespBody(resp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errReadBody, err))
			continue
		}

		var nvdCvesHistoryResp *model.NvdCvesHistoryResp = new(model.NvdCvesHistoryResp)
		err = parseRespBody(body, nvdCvesHistoryResp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errParseBody, err))
			continue
		}

		totalResults = nvdCvesHistoryResp.TotalResults
		break
	}
	return totalResults
}
