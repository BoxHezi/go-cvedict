package model

import (
	"fmt"
	"os"
)

const (
	YEAR_START_IDX = 4
	YEAR_END_IDX   = 8
)

type Cve struct {
	Id               string          `json:"id"`
	SourceIdentifier string          `json:"sourceIdentifier"`
	Published        string          `json:"published"`
	LastModified     string          `json:"lastModified"`
	Status           string          `json:"vulnStatus"`
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
	CvssMetricV31 []cvss31 `json:"cvssMetricV31,omitempty"`
	CvssMetricV30 []cvss30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []cvss2  `json:"cvssMetricV2,omitempty"`
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
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float32 `json:"baseScore"`
	// CVSS3.0 & CVSS3.1
	AttackVector       string `json:"attackVector"`
	AttackComplexity   string `json:"attackComplexity"`
	PrivilegesRequired string `json:"privilegesRequired"`
	UserInteraction    string `json:"userInteraction"`
	Scope              string `json:"scope"`
	BaseSeverity       string `json:"baseSeverity"`
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
	return c.Id[YEAR_START_IDX:YEAR_END_IDX]
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

// func (change CveChange) GetCveId() string {
// 	return change.CveId
// }
