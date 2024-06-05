package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	model "cve-dict/model"
)

const (
	nvdUrl        string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdHistoryUrl string = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
	incremental   int    = 2000
)

func currentHourMinuteSecond() string {
	return fmt.Sprintf("%02d:%02d:%02d", time.Now().Hour(), time.Now().Minute(), time.Now().Second())
}

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

func nvdKey() string {
	return os.Getenv("NVD_KEY")
}

func waitForNextRequest(start, end time.Time, key string) {
	duration := end.Sub(start)
	waitBase := 6 * time.Second

	if key != "" {
		// NVD API rate limit is 0.6 request/second
		waitBase = 1 * time.Second
	}

	if duration < waitBase {
		time.Sleep(waitBase - duration)
	}
}

func sendQuery(url string, key string) *http.Response {
	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	if key != "" {
		req.Header.Set("apiKey", nvdKey())
	}
	fmt.Println(currentHourMinuteSecond(), url)
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

func parseRespBody(body []byte) (model.NvdCvesResp, error) {
	var bodyJson model.NvdCvesResp
	if err := json.Unmarshal(body, &bodyJson); err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
		}
		return model.NvdCvesResp{}, err
	}

	return bodyJson, nil
}

func fetchAll() []model.Cve {
	var index int = 0
	var totalResults int = 0
	var cves []model.Cve = []model.Cve{}

	key := nvdKey()

	fmt.Println(currentHourMinuteSecond(), "-", "Start Fetching CVEs from NVD...")
	start := time.Now()
	for {
		endpoint := constructUrl(nvdUrl, map[string]string{"startIndex": fmt.Sprintf("%d", index)})
		t1 := time.Now()
		// Send Request
		resp := sendQuery(endpoint, key)

		// Read Response Body
		body := readRespBody(resp)
		t2 := time.Now()

		// Parse Response Body to CVE/JSONs
		bodyJson, err := parseRespBody(body)
		if err != nil {
			fmt.Println("Wait for 6 seconds and try again...")
			time.Sleep(6 * time.Second)
			continue
		}

		cves = append(cves, bodyJson.UnpackCve()...) // store all vulns into a slice/arrays

		totalResults = bodyJson.TotalResults
		// resp.Body.Close()
		index += incremental
		if index >= totalResults {
			break
		}

		waitForNextRequest(t1, t2, key) // NVD request rate limit: 6 seconds per request if without API key; 1 second per request if with API key
	}
	fmt.Println(currentHourMinuteSecond(), "-", "Done Fetching CVEs from NVD...")
	end := time.Now()
	totalDuration := end.Sub(start)
	fmt.Printf("Fetched %d CVEs in %v\n", len(cves), totalDuration)

	return cves
}

func FetchCves(param map[string]string) []model.Cve {
	if param == nil {
		return fetchAll()
	}

	var cves []model.Cve = []model.Cve{}
	endpoint := constructUrl(nvdUrl, param)
	resp := sendQuery(endpoint, nvdKey())
	defer resp.Body.Close()

	body := readRespBody(resp)

	var bodyJson model.NvdCvesResp
	if err := json.Unmarshal(body, &bodyJson); err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
		}
		log.Fatal(err)
	}

	cves = bodyJson.UnpackCve()
	return cves
}

func FetchCvesHistory(param map[string]string) []model.CveChange {
	var cveChanges []model.CveChange
	endpoint := constructUrl(nvdHistoryUrl, param)

	resp := sendQuery(endpoint, nvdKey())
	defer resp.Body.Close()

	body := readRespBody(resp)

	var bodyJson model.NvdCvesHistoryResp
	if err := json.Unmarshal(body, &bodyJson); err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
		}
		log.Fatal(err)
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

	t1 := time.Now()

	// query cve endpoint to set up the number of CVEs
	status.SetCveCount(initNvdCveStatus())

	t2 := time.Now()
	waitForNextRequest(t1, t2, "")

	// query cve history endpoint to set up the number of CVE history
	status.SetCveHistoryCount(initNvdCveHistoryStatus())

	return *status
}

func initNvdCveStatus() int {
	endpoint := constructUrl(nvdUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
	resp := sendQuery(endpoint, nvdKey())
	defer resp.Body.Close()

	body := readRespBody(resp)

	var cveResp model.NvdCvesResp
	if err := json.Unmarshal(body, &cveResp); err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
		}
		log.Fatal(err)
	}
	return cveResp.TotalResults
}

func initNvdCveHistoryStatus() int {
	endpoint := constructUrl(nvdHistoryUrl, map[string]string{"startIndex": "0", "resultsPerPage": "1"})
	resp := sendQuery(endpoint, nvdKey())
	defer resp.Body.Close()

	body := readRespBody(resp)

	var cveHistoryResp model.NvdCvesHistoryResp
	if err := json.Unmarshal(body, &cveHistoryResp); err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
		}
		log.Fatal(err)
	}
	return cveHistoryResp.TotalResults
}
