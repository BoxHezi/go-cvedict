package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

func FetchAll() {
	var index int = 0
	var totalResults int = 0
	var count int = 0

	fmt.Println(currentHourMinuteSecond())
	for {
		tempUrl := constructUrlByIndex(index)
		fmt.Println(currentHourMinuteSecond(), " ", tempUrl)

		// Query NVD API
		data, err := http.Get(tempUrl)
		if err != nil {
			log.Fatal(err)
		}
		// defer data.Body.Close()
		t1 := time.Now()
		// fmt.Println(t1)

		// Read Response Body
		body, err := io.ReadAll(data.Body) // time-consuming
		if err != nil {
			log.Fatal(err)
		}
		t2 := time.Now()
		// fmt.Println(t2)

		duration := t2.Sub(t1) // calculate time taken for: 1. send and receive request; 2. parse response
		// fmt.Println("Duration: ", duration)
		// fmt.Println("Duration: ", int(duration.Seconds()))

		// Parse Response Body to CVE/JSON
		var bodyJson map[string]interface{}
		if err := json.Unmarshal(body, &bodyJson); err != nil {
			log.Fatal(err)
		}

		tempVulns := bodyJson["vulnerabilities"].([]interface{})
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
		// time.Sleep(time.Second * 6)
		// fmt.Println("Duration: ", duration)
		if duration.Seconds() < 6 {
			sleep := time.Duration(6 - int(duration.Seconds()))
			// fmt.Printf("Wait for %d seconds\n", sleep)
			time.Sleep(time.Second * sleep)
		}
	}
	fmt.Println(currentHourMinuteSecond())
	fmt.Printf("Total %d CVEs fetched\n", count)
}
