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

// UnpackCve returns a slice of Cve structs by unpacking the Cve field from each nvdRespCve struct in the Vulnerabilities field of the NvdResp struct.
//
// No parameters.
// Returns a slice of Cve structs.
func (n NvdResp) UnpackCve() []Cve {
	var cves []Cve
	for _, v := range n.Vulnerabilities {
		cves = append(cves, v.Cve)
	}
	return cves
}
