package model

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	utils "cve-dict/utils"
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

func (n *NvdRequest) ParseParams(params map[string]string) string {
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

func (n *NvdRequest) Prepare(baseUrl string, params map[string]string) {
	n.SetBaseUrl(baseUrl)
	n.ParseParams(params)
}

func (n *NvdRequest) Send() *http.Response {
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
		fmt.Println("Error when sending request")
		log.Fatal(err)
	}
	return resp
}

func (n *NvdRequest) FullReqUrl() string {
	return fmt.Sprintf("%s?%s", n.baseUrl, n.paramString)
}

// NVD request rate limit: 6 seconds per request if without API key; 1 second per request if with API key
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
