package model

// https://services.nvd.nist.gov/rest/json/cves/2.0
type NvdCvesResp struct {
	ResultsPerPage  int      `json:"resultsPerPage"`
	StartIndex      int      `json:"startIndex"`
	TotalResults    int      `json:"totalResults"`
	Format          string   `json:"format"`
	Version         string   `json:"version"`
	Timestamp       string   `json:"timestamp"`
	Vulnerabilities []nvdCve `json:"vulnerabilities"` // nvd response: list of CVE json object
}

type nvdCve struct {
	Cve Cve `json:"cve"`
}

// https://services.nvd.nist.gov/rest/json/cvehistory/2.0
type NvdCvesHistoryResp struct {
	ResultsPerPage int            `json:"resultsPerPage"`
	StartIndex     int            `json:"startIndex"`
	TotalResults   int            `json:"totalResults"`
	Format         string         `json:"format"`
	Version        string         `json:"version"`
	Timestamp      string         `json:"timestamp"`
	CveChanges     []nvdCveChange `json:"cveChanges"`
}

type nvdCveChange struct {
	Change CveChange `json:"change"`
}

// UnpackCve returns a slice of Cve structs by unpacking the Cve field from each nvdRespCve struct in the Vulnerabilities field of the NvdResp struct.
//
// No parameters.
// Returns a slice of Cve structs.
func (n NvdCvesResp) UnpackCve() []Cve {
	var cves []Cve
	for _, v := range n.Vulnerabilities {
		cves = append(cves, v.Cve)
	}
	return cves
}

// UnpackCveChange returns a slice of CveChange structs by unpacking the Change field from each nvdCveChange struct in the CveChanges field of the NvdCvesHistoryResp struct.
//
// No parameters.
// Returns a slice of CveChange structs.
func (n NvdCvesHistoryResp) UnpackCveChange() []CveChange {
	var cveChanges []CveChange
	for _, v := range n.CveChanges {
		cveChanges = append(cveChanges, v.Change)
	}
	return cveChanges
}
