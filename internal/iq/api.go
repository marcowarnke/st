package iq

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Stages IQ Server evaluates in, in pipeline order.
var Stages = []string{"develop", "source", "build", "stage-release", "release", "operate"}

type Application struct {
	ID              string `json:"id"`
	PublicID        string `json:"publicId"`
	Name            string `json:"name"`
	OrganizationID  string `json:"organizationId"`
	ContactUserName string `json:"contactUserName,omitempty"`
}

// Applications lists every application the user can see.
func (c *Client) Applications() ([]Application, error) {
	var out struct {
		Applications []Application `json:"applications"`
	}
	err := c.Do("GET", "api/v2/applications", nil, nil, &out)
	return out.Applications, err
}

// Application looks an application up by public ID.
func (c *Client) Application(publicID string) (*Application, error) {
	var out struct {
		Applications []Application `json:"applications"`
	}
	if err := c.Do("GET", "api/v2/applications", url.Values{"publicId": {publicID}}, nil, &out); err != nil {
		return nil, err
	}
	if len(out.Applications) == 0 {
		return nil, fmt.Errorf("no application with public ID %q (or no permission to view it)", publicID)
	}
	return &out.Applications[0], nil
}

type SourceControl struct {
	RepositoryURL string `json:"repositoryUrl"`
	BaseBranch    string `json:"baseBranch"`
}

// SourceControl returns the application's SCM configuration, nil if none.
func (c *Client) SourceControl(appID string) (*SourceControl, error) {
	var sc SourceControl
	err := c.Do("GET", "api/v2/sourceControl/application/"+url.PathEscape(appID), nil, nil, &sc)
	if IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sc, nil
}

// ReportInfo is one entry of an application's latest reports (one per stage).
type ReportInfo struct {
	Stage               string `json:"stage"`
	ApplicationID       string `json:"applicationId"`
	EvaluationDate      string `json:"evaluationDate"`
	LatestReportHTMLURL string `json:"latestReportHtmlUrl"`
	ReportHTMLURL       string `json:"reportHtmlUrl"`
	ReportDataURL       string `json:"reportDataUrl"`
}

// ReportID is the last path segment of reportDataUrl
// ("api/v2/applications/<publicId>/reports/<reportId>").
func (r ReportInfo) ReportID() string {
	u := strings.TrimRight(r.ReportDataURL, "/")
	return u[strings.LastIndex(u, "/")+1:]
}

// Reports returns the most recent report per stage, in pipeline order.
func (c *Client) Reports(appID string) ([]ReportInfo, error) {
	var out []ReportInfo
	if err := c.Do("GET", "api/v2/reports/applications/"+url.PathEscape(appID), nil, nil, &out); err != nil {
		return nil, err
	}
	rank := func(s string) int {
		for i, st := range Stages {
			if st == s {
				return i
			}
		}
		return len(Stages)
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Stage) < rank(out[j].Stage) })
	return out, nil
}

// ComponentIdentifier is IQ's {format, coordinates} component key.
type ComponentIdentifier struct {
	Format      string         `json:"format"`
	Coordinates map[string]any `json:"coordinates"`
}

// Version returns coordinates.version, if any.
func (ci *ComponentIdentifier) Version() string {
	if ci == nil {
		return ""
	}
	if v, ok := ci.Coordinates["version"].(string); ok {
		return v
	}
	return ""
}

type SecurityIssue struct {
	Source         string  `json:"source"`
	Reference      string  `json:"reference"`
	Severity       float64 `json:"severity"`
	Status         string  `json:"status"`
	URL            string  `json:"url"`
	ThreatCategory string  `json:"threatCategory"`
}

type DependencyData struct {
	DirectDependency     bool     `json:"directDependency"`
	InnerSource          bool     `json:"innerSource"`
	ParentComponentPurls []string `json:"parentComponentPurls"`
}

type RawComponent struct {
	Hash                string               `json:"hash"`
	ComponentIdentifier *ComponentIdentifier `json:"componentIdentifier"`
	PackageURL          string               `json:"packageUrl"`
	DisplayName         string               `json:"displayName"`
	Proprietary         bool                 `json:"proprietary"`
	MatchState          string               `json:"matchState"`
	Pathnames           []string             `json:"pathnames"`
	SecurityData        *struct {
		SecurityIssues []SecurityIssue `json:"securityIssues"`
	} `json:"securityData"`
	DependencyData *DependencyData `json:"dependencyData"`
}

// RawReport returns the component, vulnerability and dependency data of a report.
func (c *Client) RawReport(publicID, reportID string) ([]RawComponent, error) {
	var out struct {
		Components []RawComponent `json:"components"`
	}
	err := c.Do("GET", "api/v2/applications/"+url.PathEscape(publicID)+"/reports/"+url.PathEscape(reportID)+"/raw", nil, nil, &out)
	return out.Components, err
}

type Condition struct {
	ConditionSummary string `json:"conditionSummary"`
	ConditionReason  string `json:"conditionReason"`
}

type Constraint struct {
	ConstraintID   string      `json:"constraintId"`
	ConstraintName string      `json:"constraintName"`
	Conditions     []Condition `json:"conditions"`
}

type Violation struct {
	PolicyID             string       `json:"policyId"`
	PolicyName           string       `json:"policyName"`
	PolicyThreatCategory string       `json:"policyThreatCategory"`
	PolicyThreatLevel    int          `json:"policyThreatLevel"`
	Waived               bool         `json:"waived"`
	Grandfathered        bool         `json:"grandfathered"`
	LegacyViolation      bool         `json:"legacyViolation"`
	Constraints          []Constraint `json:"constraints"`
}

// Security reports whether the violation comes from a security policy.
func (v Violation) Security() bool { return strings.EqualFold(v.PolicyThreatCategory, "SECURITY") }

type PolicyComponent struct {
	Hash                string               `json:"hash"`
	ComponentIdentifier *ComponentIdentifier `json:"componentIdentifier"`
	PackageURL          string               `json:"packageUrl"`
	DisplayName         string               `json:"displayName"`
	Violations          []Violation          `json:"violations"`
	DependencyData      *DependencyData      `json:"dependencyData"`
}

type PolicyReport struct {
	ReportTime  int64             `json:"reportTime"`
	ReportTitle string            `json:"reportTitle"`
	CommitHash  string            `json:"commitHash"`
	Initiator   string            `json:"initiator"`
	Application Application       `json:"application"`
	Components  []PolicyComponent `json:"components"`
}

// PolicyReport returns the policy evaluation (violations) of a report.
func (c *Client) PolicyReport(publicID, reportID string) (*PolicyReport, error) {
	var out PolicyReport
	err := c.Do("GET", "api/v2/applications/"+url.PathEscape(publicID)+"/reports/"+url.PathEscape(reportID)+"/policy", nil, nil, &out)
	return &out, err
}

type RemediationComponent struct {
	PackageURL          string               `json:"packageUrl"`
	Hash                *string              `json:"hash"`
	ComponentIdentifier *ComponentIdentifier `json:"componentIdentifier"`
	DisplayName         string               `json:"displayName"`
}

type VersionChange struct {
	Type string `json:"type"`
	Data struct {
		Component RemediationComponent `json:"component"`
	} `json:"data"`
	// Only set with includeParentRemediation.
	DirectDependency     *bool `json:"directDependency"`
	DirectDependencyData []struct {
		Component RemediationComponent `json:"component"`
	} `json:"directDependencyData"`
}

// Remediation asks IQ Server which versions of a component would fix its
// policy violations in the application. stage is needed for the
// next-non-failing strategies.
func (c *Client) Remediation(appID, stage string, ci *ComponentIdentifier) ([]VersionChange, error) {
	q := url.Values{"includeParentRemediation": {"true"}}
	if stage != "" {
		q.Set("stageId", stage)
	}
	var out struct {
		Remediation struct {
			VersionChanges []VersionChange `json:"versionChanges"`
		} `json:"remediation"`
	}
	err := c.Do("POST", "api/v2/components/remediation/application/"+url.PathEscape(appID), q,
		map[string]any{"componentIdentifier": ci}, &out)
	return out.Remediation.VersionChanges, err
}

type Vulnerability struct {
	Identifier        string   `json:"identifier"`
	VulnIDs           []string `json:"vulnIds"`
	VulnerabilityLink string   `json:"vulnerabilityLink"`
	Source            *struct {
		ShortName string `json:"shortName"`
		LongName  string `json:"longName"`
	} `json:"source"`
	MainSeverity   *Severity  `json:"mainSeverity"`
	SeverityScores []Severity `json:"severityScores"`
	Weakness       *struct {
		CWESource string `json:"cweSource"`
		CWEIDs    []struct {
			ID  string `json:"id"`
			URI string `json:"uri"`
		} `json:"cweIds"`
	} `json:"weakness"`
	Categories             []string `json:"categories"`
	Description            string   `json:"description"`
	ExplanationMarkdown    string   `json:"explanationMarkdown"`
	DetectionMarkdown      string   `json:"detectionMarkdown"`
	RecommendationMarkdown string   `json:"recommendationMarkdown"`
	RootCauses             []struct {
		ListOfPaths  []string `json:"listOfPaths"`
		VersionRange string   `json:"versionRange"`
	} `json:"rootCauses"`
	Advisories []struct {
		ReferenceType string `json:"referenceType"`
		URL           string `json:"url"`
	} `json:"advisories"`
	VulnerableVersionRanges []string        `json:"vulnerableVersionRanges"`
	ResearchType            string          `json:"researchType"`
	DetectionType           string          `json:"detectionType"`
	CustomData              json.RawMessage `json:"customData,omitempty"`
	KEVData                 *struct {
		IsKEV bool `json:"isKev"`
	} `json:"kevData"`
}

type Severity struct {
	Source string  `json:"source"`
	Score  float64 `json:"score"`
	Vector string  `json:"vector,omitempty"`
}

// Vulnerability fetches details for a CVE or Sonatype vulnerability ID.
func (c *Client) Vulnerability(id string) (*Vulnerability, error) {
	var v Vulnerability
	err := c.Do("GET", "api/v2/vulnerabilities/"+url.PathEscape(id), nil, nil, &v)
	return &v, err
}
