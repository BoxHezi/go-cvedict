package model

import (
	"fmt"
	"os"
)

const (
	year_start_idx = 4
	year_end_idx   = 8
)

type Cve struct {
	Id               string          `json:"id"`
	SourceIdentifier string          `json:"sourceIdentifier"`
	Published        string          `json:"published"`
	LastModified     string          `json:"lastModified"`
	Status           string          `json:"vulnStatus"`
	CveTags          []string        `json:"cveTags"`
	Descriptions     []desc          `json:"descriptions"`
	Metrics          metrics         `json:"metrics"`
	Weaknesses       []weakness      `json:"weaknesses,omitempty"`
	Configurations   []configuration `json:"configurations,omitempty"`
	References       []reference     `json:"references"`
}

type desc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	CvssMetricV40 []cvss40 `json:"cvssMetricV40,omitempty"`
	CvssMetricV31 []cvss31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV30 []cvss30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []cvss2  `json:"cvssMetricV2,omitempty"`
}

type cvss40 struct {
	Source   string   `json:"source"`
	Type     string   `json:"type"`
	CvssData cvssdata `json:"cvssData"`
}

type cvss31 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CvssData            cvssdata `json:"cvssData"`
	ExploitabilityScore float32  `json:"exploitabilityScore"`
	ImpactScore         float32  `json:"impactScore"`
}

type cvss30 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CvssData            cvssdata `json:"cvssData"`
	ExploitabilityScore float32  `json:"exploitabilityScore"`
	ImpactScore         float32  `json:"impactScore"`
}

type cvss2 struct {
	Source                  string   `json:"source"`
	Type                    string   `json:"type"`
	CvssData                cvssdata `json:"cvssData"`
	BaseSeverity            string   `json:"baseSeverity"`
	ExploitabilityScore     float32  `json:"exploitabilityScore"`
	ImpactScore             float32  `json:"impactScore"`
	AcInsufInfo             bool     `json:"acInsufInfo"`
	ObtainAllPrivilege      bool     `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool     `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool     `json:"userInteractionRequired"`
}

type cvssdata struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float32 `json:"baseScore"`
	// CVSS4.0
	AttackRequirements                      string `json:"attackrequirements"`
	VulnerableSystemConfidentiality         string `json:"vulnerableSystemConfidentiality"`
	VulnerableSystemIntegrity               string `json:"vulnerableSystemIntegrity"`
	VulnerableSystemAvailability            string `json:"vulnerableSystemAvailability"`
	SubsequentSystemConfidentiality         string `json:"subsequentSystemConfidentiality"`
	SubsequentSystemIntegrity               string `json:"subsequentSystemIntegrity"`
	SubsequentSystemAvailability            string `json:"subsequentSystemAvailability"`
	ExploitMaturity                         string `json:"exploitMaturity"`
	ConfidentialityRequirements             string `json:"confidentialityRequirements"`
	IntegrityRequirements                   string `json:"integrityRequirements"`
	AvailabilityRequirements                string `json:"availabilityRequirements"`
	ModifiedAttackVector                    string `json:"modifiedAttackVector"`
	ModifiedAttackComplexity                string `json:"modifiedAttackComplexity"`
	ModifiedAttackRequirements              string `json:"modifiedAttackRequirements"`
	ModifiedPrivilegesRequired              string `json:"modifiedPrivilegesRequired"`
	ModifiedUserInteraction                 string `json:"modifiedUserInteraction"`
	ModifiedVulnerableSystemConfidentiality string `json:"modifiedVulnerableSystemConfidentiality"`
	ModifiedVulnerableSystemIntegrity       string `json:"modifiedVulnerableSystemIntegrity"`
	ModifiedVulnerableSystemAvailability    string `json:"modifiedVulnerableSystemAvailability"`
	ModifiedSubsequentSystemConfidentiality string `json:"modifiedSubsequentSystemConfidentiality"`
	ModifiedSubsequentSystemIntegrity       string `json:"modifiedSubsequentSystemIntegrity"`
	ModifiedSubsequentSystemAvailability    string `json:"modifiedSubsequentSystemAvailability"`
	Safety                                  string `json:"safety"`
	Automatable                             string `json:"automatable"`
	Recovery                                string `json:"recovery"`
	ValueDensity                            string `json:"valueDensity"`
	VulnerabilityResponseEffort             string `json:"vulnerabilityResponseEffort"`
	ProviderUrgency                         string `json:"providerUrgency"`
	// CVSS4.0 & CVSS3.0 & CVSS3.1
	AttackVector       string `json:"attackVector"`
	AttackComplexity   string `json:"attackComplexity"`
	PrivilegesRequired string `json:"privilegesRequired"`
	UserInteraction    string `json:"userInteraction"`
	BaseSeverity       string `json:"baseSeverity"`
	// CVSS3.0 & CVSS3.1
	Scope string `json:"scope"`
	// CVSS3.0 & CVSS3.1 & CVSS2.0
	ConfidentialityImpact string `json:"confidentialityImpact"`
	IntegrityImpact       string `json:"integrityImpact"`
	AvailabilityImpact    string `json:"availabilityImpact"`
	// CVSS2.0
	AccessVector     string `json:"accessVector"`
	AccessComplexity string `json:"accessComplexity"`
	Authentication   string `json:"authentication"`
}

type weakness struct {
	Source       string         `json:"source"`
	Type         string         `json:"type"`
	Descriptions []weaknessDesc `json:"description"`
}

type weaknessDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type configuration struct {
	Operator string `json:"operator"`
	Nodes    []node `json:"nodes"`
}

type node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CpeMatch []cpeMatch `json:"cpeMatch"`
}

type cpeMatch struct {
	Vulnerable          bool   `json:"vulnerable"`
	Criteria            string `json:"criteria"`
	VersionEndIncluding string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
	MatchCriteriaId     string `json:"matchCriteriaId"`
}

type reference struct {
	Url    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

// Cve Change
type CveChange struct {
	CveId            string   `json:"cveId"`
	EventName        string   `json:"eventName"` //? CVE Received, CVE Modified, Initial Analysis
	CveChangeId      string   `json:"cveChangeId"`
	SourceIdentifier string   `json:"sourceIdentifier"`
	Created          string   `json:"created"`
	Details          []detail `json:"details"`
}

type detail struct {
	Action   string `json:"action"` //? TODO: Added, Removed, Changed
	Type     string `json:"type"`
	OldValue string `json:"oldValue,omitempty"`
	NewValue string `json:"newValue,omitempty"`
}

func (c Cve) CveSummary() string {
	var content string = ""
	content += fmt.Sprintf("ID: %s\n", c.Id)
	content += fmt.Sprintf("Published: %s\n", c.Published)
	content += fmt.Sprintf("Modified: %s\n", c.LastModified)
	content += fmt.Sprintf("Status: %s\n", c.Status)

	return content
}

func (c Cve) GetYear() string {
	return c.Id[year_start_idx:year_end_idx]
}

func (c Cve) GenerateFilename() string {
	homedir, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.nvdcve/%s%s.json", homedir, c.GenerateDirectoryName(), c.Id)
}

func (c Cve) GenerateDirectoryName() string {
	year := c.GetYear()
	suffix := "/" + c.Id[:len(c.Id)-2] + "xx/"
	return fmt.Sprintf("%s%s", year, suffix)
}

func (c Cve) filterCvss31(cvss float32) bool {
	if c.Metrics.CvssMetricV31 != nil {
		for _, metrics := range c.Metrics.CvssMetricV31 {
			if metrics.CvssData.BaseScore >= cvss {
				// fmt.Println(c.Id, "CVSS31", metrics.CvssData.BaseScore)
				return true
			}
		}
	}
	return false
}

func (c Cve) filterCvss30(cvss float32) bool {
	if c.Metrics.CvssMetricV30 != nil {
		for _, metrics := range c.Metrics.CvssMetricV30 {
			if metrics.CvssData.BaseScore >= cvss {
				// fmt.Println(c.Id, "CVSS30", metrics.CvssData.BaseScore)
				return true
			}
		}
	}
	return false
}

func (c Cve) filterCvss2(cvss float32) bool {
	if c.Metrics.CvssMetricV2 != nil {
		for _, metrics := range c.Metrics.CvssMetricV2 {
			if metrics.CvssData.BaseScore >= cvss {
				// fmt.Println(c.Id, "CVSS2", metrics.CvssData.BaseScore)
				return true
			}
		}
	}
	return false
}

func (c Cve) FilterCvss(cvss float32) bool {
	if c.filterCvss31(cvss) || c.filterCvss30(cvss) || c.filterCvss2(cvss) {
		return true
	}
	return false
}

// func (change CveChange) GetCveId() string {
// 	return change.CveId
// }
