package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	model "cve-dict/model"

	utils "cve-dict/utils"
)

const (
	nvdUrl        string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdHistoryUrl string = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
	incremental   int    = 2000
)

var (
	nvdReq *model.NvdRequestStatus = model.CreateNvdRequestStatus()
)

func constructUrl(baseUrl string, param map[string]string) string {
	var p string // parameters string
	var c int    // counter
	for k, v := range param {
		if c > 0 {
			p += "&"
		}
		p += fmt.Sprintf("%s=%s", k, v)
		c++
	}
	return fmt.Sprintf("%s?%s", baseUrl, p)
}

func sendQuery(url string) *http.Response {
	nvdReq.Wait()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	if nvdReq.NvdKey != "" {
		req.Header.Set("apiKey", nvdReq.NvdKey)
	}
	utils.LogInfo(url)

	nvdReq.SetReqTime(time.Now())
	nvdReq.SetReqUrl(url)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error when sending request")
		log.Fatal(err)
	}
	return resp
}

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

// func fetchAll() []model.Cve {
// 	var index int = 0
// 	var totalResults int = 0
// 	var cves []model.Cve = []model.Cve{}

// 	// fmt.Println(currentHourMinuteSecond(), "-", "Start Fetching CVEs from NVD...")
// 	utils.LogInfo("Start Fetching CVEs from NVD...")
// 	start := time.Now()
// 	for {
// 		url := constructUrl(nvdUrl, map[string]string{"startIndex": fmt.Sprintf("%d", index)})
// 		resp := sendQuery(url)
// 		body := readRespBody(resp)

// 		// Parse Response Body to CVE/JSONs
// 		var bodyJson *model.NvdCvesResp = new(model.NvdCvesResp)
// 		err := parseRespBody(body, bodyJson)
// 		if err != nil {
// 			fmt.Printf("Try again: %s\n", url)
// 			continue
// 		}

// 		cves = append(cves, bodyJson.UnpackCve()...) // store all vulns into a slice/arrays

// 		totalResults = bodyJson.TotalResults
// 		index += incremental
// 		if index >= totalResults {
// 			break
// 		}
// 	}
// 	utils.LogInfo("Done Fetching CVEs from NVD...")
// 	end := time.Now()
// 	totalDuration := end.Sub(start)
// 	fmt.Printf("Fetched %d CVEs in %v\n", len(cves), totalDuration)

// 	return cves
// }

func FetchCves(param map[string]string) []model.Cve {
	var cves []model.Cve = []model.Cve{}
	for { // add loop to retry if error occurs
		url := constructUrl(nvdUrl, param)
		resp := sendQuery(url)
		body := readRespBody(resp)

		var bodyJson *model.NvdCvesResp = new(model.NvdCvesResp)
		err := parseRespBody(body, bodyJson)
		if err != nil {
			fmt.Printf("Try again: %s\n", url)
			continue
		}

		cves = bodyJson.UnpackCve()
		break
	}

	return cves
}

func FetchCvesHistory(param map[string]string) []model.CveChange {
	var cveChanges []model.CveChange
	url := constructUrl(nvdHistoryUrl, param)
	resp := sendQuery(url)
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
	url := constructUrl(nvdUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
	resp := sendQuery(url)
	body := readRespBody(resp)

	var bodyJson *model.NvdCvesResp = new(model.NvdCvesResp)
	err := parseRespBody(body, bodyJson)
	if err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
	}
	return bodyJson.TotalResults
}

func initNvdCveHistoryStatus() int {
	url := constructUrl(nvdHistoryUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
	resp := sendQuery(url)
	body := readRespBody(resp)

	var bodyJson *model.NvdCvesHistoryResp = new(model.NvdCvesHistoryResp)
	err := parseRespBody(body, bodyJson)
	if err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
	}
	return bodyJson.TotalResults
}
