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
	cveServices "cve-dict/services/cve"
)

const (
	nvdUrl      string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	incremental int    = 2000
)

func currentHourMinuteSecond() string {
	return fmt.Sprintf("%02d:%02d:%02d", time.Now().Hour(), time.Now().Minute(), time.Now().Second())
}

func constructUrl(param map[string]string) string {
	var endpoint string = nvdUrl

	var p string
	var c int // counter
	for k, v := range param {
		if c > 0 {
			p += "&"
		}
		p += fmt.Sprintf("%s=%s", k, v)
		c++
	}
	return fmt.Sprintf("%s?%s", endpoint, p)
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
		// waiting := (waitBase - duration).Seconds()
		// fmt.Printf("Wait for %f seconds\n", waiting)
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

func FetchAll() []model.Cve {
	var index int = 0
	var totalResults int = 0
	var cves []model.Cve = []model.Cve{}

	key := nvdKey()

	fmt.Println(currentHourMinuteSecond(), "-", "Start Fetching CVEs from NVD...")
	// start := time.Now()
	for {
		endpoint := constructUrl(map[string]string{"startIndex": fmt.Sprintf("%d", index)})
		t1 := time.Now()
		// Send Request
		resp := sendQuery(endpoint, key)

		// Read Response Body
		body := readRespBody(resp)
		t2 := time.Now()

		// Parse Response Body to CVE/JSONs
		bodyJson, err := parseRespBody(body)
		if err != nil {
			fmt.Printf("Error when parsing response body: %s\n", err)
			fmt.Println("Wait for 6 seconds and try again...")
			time.Sleep(6 * time.Second)
			continue
		}

		cves = append(cves, bodyJson.UnpackCve()...) // store all vulns into a slice/arrays

		totalResults = bodyJson.TotalResults
		resp.Body.Close()
		index += incremental
		if index >= totalResults {
			break
		}

		waitForNextRequest(t1, t2, key) // NVD request rate limit: 6 seconds per request if without API key; 1 second per request if with API key
	}
	fmt.Println(currentHourMinuteSecond(), " - ", "Done Fetching CVEs from NVD...")
	fmt.Printf("Total %d CVEs fetched\n", totalResults)
	// fmt.Printf("len(cves): %d\n", len(cves))
	// fmt.Printf("Total %d CVEs fetched\n", count)

	// end := time.Now()

	// if key != "" {
	// 	fmt.Printf("With API Key - ")
	// } else {
	// 	fmt.Printf("Without API Key - ")
	// }
	// totalDuration := end.Sub(start)
	// fmt.Println("Total Duration: ", totalDuration)

	for _, c := range cves {
		// c.WriteToFile(c.GenerateFilename())
		cveServices.WriteToFile(c, "")
	}

	return cves
}

func FetchCveById(id string) model.Cve {
	endpoint := constructUrl(map[string]string{"cveId": id})
	fmt.Println(endpoint)

	resp, err := http.Get(endpoint)
	if err != nil {
		fmt.Println("Error when sending request")
		log.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error when reading response body")
		log.Fatal(err)
	}

	var bodyJson model.NvdCvesResp
	if err := json.Unmarshal(data, &bodyJson); err != nil {
		fmt.Printf("Error when parsing response body: %s\n", err)
		if e, ok := err.(*json.SyntaxError); ok {
			fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
		}
		log.Fatal(err)
	}

	return bodyJson.UnpackCve()[0]
}

// func FetchCve(param map[string]string) []model.Cve {
// 	if param == nil {
// 		return FetchAll()
// 	}
// 	return nil
// }
