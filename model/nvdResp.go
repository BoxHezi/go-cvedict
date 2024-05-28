package model

type NvdResp struct {
	ResultsPerPage  int          `json:"resultsPerPage"`
	StartIndex      int          `json:"startIndex"`
	TotalResults    int          `json:"totalResults"`
	Format          string       `json:"format"`
	Version         string       `json:"version"`
	Timestamp       string       `json:"timestamp"`
	Vulnerabilities []nvdRespCve `json:"vulnerabilities"` // nvd response: list of CVE json object
}

type nvdRespCve struct {
	Cve Cve `json:"cve"`
}
