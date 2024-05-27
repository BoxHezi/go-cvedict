package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	nvdUrl      string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	incremental int    = 2000
)

func currentHourMinuteSecond() string {
	return fmt.Sprintf("%02d:%02d:%02d", time.Now().Hour(), time.Now().Minute(), time.Now().Second())
}

func constructUrlByIndex(index int) string {
	return fmt.Sprintf(nvdUrl+"?startIndex=%d", index)
}

func nvdKey() string {
	return os.Getenv("NVD_KEY")
}

func waitForNextRequest(start, end time.Time, key string) {
	duration := end.Sub(start)
	waitBase := 6 * time.Second

	if key != "" {
		waitBase = 1 * time.Second
	}

	// fmt.Printf("Duration: %v\n", duration)
	// fmt.Printf("WaitBase: %v\n", waitBase)
	if duration < waitBase {
		waiting := (waitBase - duration).Seconds()
		fmt.Printf("Wait for %f seconds\n", waiting)
		time.Sleep(waitBase - duration)
	}
}

func sendQuery(index int, key string) *http.Response {
	tempUrl := constructUrlByIndex(index)
	fmt.Println(currentHourMinuteSecond(), " ", tempUrl)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", tempUrl, nil)
	if key != "" {
		req.Header.Set("apiKey", nvdKey())
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error when sending request")
		log.Fatal(err)
	}
	return resp
}

func FetchAll() {
	var index int = 0
	var totalResults int = 0
	var count int = 0

	key := nvdKey()
	fmt.Printf("NVD KEY: %s\n", key)

	fmt.Println(currentHourMinuteSecond())
	start := time.Now()
	for {
		// TODO: test time usage for: 1. send request 2. read response body 3. parse response body

		t1 := time.Now()
		// fmt.Println(t1)
		// Send Request
		data := sendQuery(index, key)

		// Read Response Body
		body, err := io.ReadAll(data.Body) // time-consuming
		if err != nil {
			fmt.Println("Error when reading response body")
			log.Fatal(err)
		}
		t2 := time.Now()
		// fmt.Println(t2)

		// Parse Response Body to CVE/JSON
		var bodyJson map[string]interface{}
		if err := json.Unmarshal(body, &bodyJson); err != nil {
			fmt.Printf("Error when parsing response body: %s\n", err)
			// log.Fatal(err)
			if e, ok := err.(*json.SyntaxError); ok {
				fmt.Printf("Syntax error at byte offset %d\n", e.Offset)
			}
			time.Sleep(6 * time.Second)
			continue
		}

		tempVulns := bodyJson["vulnerabilities"].([]interface{}) // TODO: store all vulns into a slice/array
		count += len(tempVulns)

		// Get Total Results
		if totalResults < int(bodyJson["totalResults"].(float64)) {
			totalResults = int(bodyJson["totalResults"].(float64))
		}

		data.Body.Close()
		index += incremental
		if index >= totalResults {
			break
		}

		//
		waitForNextRequest(t1, t2, key)
	}
	fmt.Println(currentHourMinuteSecond())
	fmt.Printf("Total %d CVEs fetched\n", count)

	end := time.Now()

	if key != "" {
		fmt.Printf("With API Key - ")
	} else {
		fmt.Printf("Without API Key - ")
	}
	totalDuration := end.Sub(start)
	fmt.Println("Total Duration: ", totalDuration)
}
