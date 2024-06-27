package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	model "cvedict/model"
	utils "cvedict/utils"
)

const (
	nvdUrl        string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdHistoryUrl string = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

	errSendRequestHint string = "error when sending request"
	errReadBodyHint    string = "error when reading response body"
	errParseBodyHint   string = "error when parsing response body"
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

// doRequest sends a request and parses the response into the provided data structure.
// type of data structure should be either model.NvdCvesResp or model.NvdCvesHistoryResp
//
// data *T: a pointer to the data structure where the response will be parsed into.
// No return value.
func doRequest[T model.NvdCvesResp | model.NvdCvesHistoryResp](data *T) {
	var count int = 0
	for {
		if count >= 10 {
			utils.LogFatal(fmt.Errorf("reach maximum retry. abort.\nrequest URL: %s", nvdReq.FullReqUrl()))
		}

		resp, err := nvdReq.Send()
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errSendRequestHint, err))
			count++
			continue
		}

		body, err := readRespBody(resp)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errReadBodyHint, err))
			count++
			continue
		}

		err = parseRespBody(body, data)
		if err != nil {
			utils.LogError(fmt.Errorf("%s: %s", errParseBodyHint, err))
			count++
			continue
		}

		// utils.LogDebug(fmt.Sprintf("\n%+v\n", container))
		return
	}
}

func FetchCves(params map[string]string) []model.Cve {
	nvdReq.Prepare(nvdUrl, params)

	var nvdCvesResp *model.NvdCvesResp = new(model.NvdCvesResp)
	doRequest(nvdCvesResp)
	return nvdCvesResp.UnpackCve()
}

func FetchCvesHistory(params map[string]string) []model.CveChange {
	nvdReq.Prepare(nvdHistoryUrl, params)

	var nvdCvesHistoryResp *model.NvdCvesHistoryResp = new(model.NvdCvesHistoryResp)
	doRequest(nvdCvesHistoryResp)
	return nvdCvesHistoryResp.UnpackCveChange()
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

	var nvdCvesResp *model.NvdCvesResp = new(model.NvdCvesResp)
	doRequest(nvdCvesResp)
	return nvdCvesResp.TotalResults
}

func initNvdCveHistoryStatus() int {
	nvdReq.Prepare(nvdHistoryUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})

	var nvdCvesHistoryResp *model.NvdCvesHistoryResp = new(model.NvdCvesHistoryResp)
	doRequest(nvdCvesHistoryResp)
	return nvdCvesHistoryResp.TotalResults
}
