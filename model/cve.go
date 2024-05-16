package model

import "fmt"

const (
	YEAR_START_INX = 4
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
	Weaknesses       []weakness      `json:"weaknesses"`
	Configurations   []configuration `json:"configurations"`
	References       []reference     `json:"references"`
}

type desc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type metrics struct {
	CvssMetricV31 []cvss31 `json:"cvssMetricV31"`
	CvssMetricV30 []cvss30 `json:"cvssMetricV30"`
	CvssMetricV2  []cvss2  `json:"cvssMetricV2"`
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
	Source       string        `json:"source"`
	Type         string        `json:"type"`
	Descriptions []weaknesDesc `json:"description"`
}

type weaknesDesc struct {
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
	Vulnerable      bool   `json:"vulnerable"`
	Criteria        string `json:"criteria"`
	MatchCriteriaId string `json:"matchCriteriaId"`
}

type reference struct {
	Url    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

func (c Cve) CveSummary() string {
	var content string = ""
	content += fmt.Sprintf("ID: %s\n", c.Id)
	content += fmt.Sprintf("Published: %s\n", c.Published)
	content += fmt.Sprintf("Modified: %s\n", c.LastModified)

	return content
}

func (c Cve) GetYear() string {
	return c.Id[YEAR_START_INX:YEAR_END_IDX]
}
