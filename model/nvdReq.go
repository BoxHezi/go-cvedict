package model

import (
	"os"
	"time"
)

// const (
// 	nvdUrl        string = "https://services.nvd.nist.gov/rest/json/cves/2.0"
// 	nvdHistoryUrl string = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
// 	incremental   int    = 2000
// )

// struct for nvd request
// holds: 1. request time 2. request url 3. nvd key
type NvdRequestStatus struct {
	ReqTime time.Time
	ReqUrl  string
	NvdKey  string
}

func CreateNvdRequestStatus() *NvdRequestStatus {
	nvdReqStatus := new(NvdRequestStatus)
	nvdReqStatus.ReqTime = time.Time{}
	nvdReqStatus.ReqUrl = ""
	nvdReqStatus.NvdKey = os.Getenv("NVD_KEY")
	return nvdReqStatus
}

// NVD request rate limit: 6 seconds per request if without API key; 1 second per request if with API key
func (n *NvdRequestStatus) Wait() {
	currentTime := time.Now()

	duration := currentTime.Sub(n.ReqTime)
	waitBase := 6 * time.Second
	if n.hasKey() {
		waitBase = 1 * time.Second
	}
	if duration < waitBase {
		time.Sleep(waitBase - duration)
	}
}

func (n *NvdRequestStatus) SetReqTime(t time.Time) {
	n.ReqTime = t
}

func (n *NvdRequestStatus) SetReqUrl(url string) {
	n.ReqUrl = url
}

func (n *NvdRequestStatus) hasKey() bool {
	return n.NvdKey != ""
}
