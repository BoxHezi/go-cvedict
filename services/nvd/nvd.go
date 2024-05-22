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

func waitForNextRequest(start, end time.Time, hasKey bool) {
	duration := end.Sub(start)
	waitBase := 6 * time.Second

	if hasKey {
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

func sendQuery(index int, hasKey bool) *http.Response {
	tempUrl := constructUrlByIndex(index)
	fmt.Println(currentHourMinuteSecond(), " ", tempUrl)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", tempUrl, nil)
	if hasKey {
		req.Header.Set("apiKey", nvdKey())
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	return resp
}

func FetchAll() {
	var index int = 0
	var totalResults int = 0
	var count int = 0

	var hasKey bool = false
	key := nvdKey()
	if key != "" {
		hasKey = true
		fmt.Println(key)
	} else {
		fmt.Println("No NVD key found")
	}

	fmt.Println(currentHourMinuteSecond())
	start := time.Now()
	for {
		// Send Request
		data := sendQuery(index, hasKey)
		t1 := time.Now()
		// fmt.Println(t1)

		// Read Response Body
		body, err := io.ReadAll(data.Body) // time-consuming
		if err != nil {
			log.Fatal(err)
		}
		t2 := time.Now()
		// fmt.Println(t2)

		// Parse Response Body to CVE/JSON
		var bodyJson map[string]interface{}
		if err := json.Unmarshal(body, &bodyJson); err != nil {
			log.Fatal(err)
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
		waitForNextRequest(t1, t2, hasKey)
	}
	fmt.Println(currentHourMinuteSecond())
	fmt.Printf("Total %d CVEs fetched\n", count)

	end := time.Now()

	totalDuration := end.Sub(start)
	fmt.Println("Total Duration: ", totalDuration)
}
