package model

import (
	"fmt"
	"net/http"
	"os"
	"time"

	utils "cvedict/utils"
)

// struct for nvd request
type NvdRequest struct {
	reqTime     time.Time
	baseUrl     string
	paramString string // parameters string
	nvdKey      string
}

func CreateNvdRequest() *NvdRequest {
	nvdReq := new(NvdRequest)
	nvdReq.reqTime = time.Time{}
	nvdReq.baseUrl = ""
	nvdReq.paramString = ""
	nvdReq.nvdKey = os.Getenv("NVD_KEY")
	return nvdReq
}

func (n *NvdRequest) parseParams(params map[string]string) string {
	var p string // parameters string
	var c int    // counter
	for k, v := range params {
		if c > 0 {
			p += "&"
		}
		p += fmt.Sprintf("%s=%s", k, v)
		c++
	}
	n.paramString = p
	return n.paramString
}

// Prepare sets the base URL and parses the parameters for the NvdRequest.
//
// Parameters:
//   - baseUrl: the base URL for the request
//   - params: a map of parameters for the request
func (n *NvdRequest) Prepare(baseUrl string, params map[string]string) {
	n.SetBaseUrl(baseUrl)
	n.parseParams(params)
}

func (n *NvdRequest) Send() (*http.Response, error) {
	n.wait()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", n.FullReqUrl(), nil)
	if n.hasKey() {
		req.Header.Set("apiKey", n.nvdKey)
	}
	utils.LogInfo(n.FullReqUrl())

	n.SetReqTime(time.Now())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (n *NvdRequest) FullReqUrl() string {
	return fmt.Sprintf("%s?%s", n.baseUrl, n.paramString)
}

// wait waits for a certain duration before allowing the next request to be sent.
//
// This function calculates the duration since the last request was sent and checks if it is less than the base wait time.
// If it is, it sleeps for the remaining time.
// The base wait time is 6 seconds for requests without an API key, and 1 second for requests with an API key.
//
// No parameters are required.
// No return values.
func (n *NvdRequest) wait() {
	currentTime := time.Now()

	duration := currentTime.Sub(n.reqTime)
	waitBase := 6 * time.Second
	if n.hasKey() {
		waitBase = 1 * time.Second
	}
	if duration < waitBase {
		time.Sleep(waitBase - duration)
	}
}

func (n *NvdRequest) SetReqTime(t time.Time) {
	n.reqTime = t
}

func (n *NvdRequest) SetBaseUrl(url string) {
	n.baseUrl = url
}

func (n *NvdRequest) SetNvdKey(key string) {
	n.nvdKey = key
}

func (n *NvdRequest) hasKey() bool {
	return n.nvdKey != ""
}
