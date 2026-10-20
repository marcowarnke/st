package cmd

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marcowarnke/st/internal/iq"
)

func newVulnCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vuln <command>",
		Aliases: []string{"vulnerability"},
		Short:   "List and view vulnerabilities",
	}
	cmd.AddCommand(newVulnListCmd(), newVulnViewCmd())
	return cmd
}

// cve is one vulnerability on a component.
type cve struct {
	ID             string  `json:"id"`
	Severity       float64 `json:"severity"`
	ThreatCategory string  `json:"threatCategory,omitempty"`
	Status         string  `json:"status,omitempty"`
	URL            string  `json:"url,omitempty"`
}

// finding is a component with security policy violations in a report.
type finding struct {
	Hash        string
	PURL        string
	Name        string
	Format      string
	Version     string
	Identifier  *iq.ComponentIdentifier
	Direct      *bool // nil: IQ didn't say
	Parents     []string
	ThreatLevel int
	Policies    []string
	Waived      bool // every security violation is waived
	CVEs        []cve
}

func (f *finding) dependency() string {
	switch {
	case f.Direct == nil:
		return "unknown"
	case *f.Direct:
		return "direct"
	}
	return "transitive"
}

func (f *finding) cveIDs() []string {
	var ids []string
	for _, c := range f.CVEs {
		ids = append(ids, c.ID)
	}
	return ids
}

// scan is the security view of one application report.
type scan struct {
	app       *iq.Application
	report    *iq.ReportInfo
	reportURL string
	findings  []finding
}

var vulnReason = regexp.MustCompile(`(?i)security vulnerability (\S+) with severity ([\d.]+)`)

// loadScan joins the policy report (violations, threat levels) with the raw
// report (CVE details, dependency data) by component hash.
func loadScan(c *session, app *iq.Application, stage string, includeWaived bool) (*scan, error) {
	rep, err := pickReport(c, app, stage)
	if err != nil {
		return nil, err
	}
	var policy *iq.PolicyReport
	var raw []iq.RawComponent
	var perr, rerr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); policy, perr = c.PolicyReport(app.PublicID, rep.ReportID()) }()
	go func() { defer wg.Done(); raw, rerr = c.RawReport(app.PublicID, rep.ReportID()) }()
	wg.Wait()
	if perr != nil {
		return nil, perr
	}
	if rerr != nil {
		return nil, rerr
	}
	rawByHash := map[string]*iq.RawComponent{}
	for i := range raw {
		rawByHash[raw[i].Hash] = &raw[i]
	}
	s := &scan{app: app, report: rep, reportURL: c.absURL(rep.ReportHTMLURL)}
	for _, pc := range policy.Components {
		var sec []iq.Violation
		active := false
		for _, v := range pc.Violations {
			if v.Security() {
				sec = append(sec, v)
				active = active || !v.Waived
			}
		}
		if len(sec) == 0 || (!active && !includeWaived) {
			continue
		}
		f := finding{Hash: pc.Hash, PURL: pc.PackageURL, Identifier: pc.ComponentIdentifier, Waived: !active}
		rc := rawByHash[pc.Hash]
		if rc != nil {
			if f.PURL == "" {
				f.PURL = rc.PackageURL
			}
			if f.Identifier == nil {
				f.Identifier = rc.ComponentIdentifier
			}
		}
		dep := pc.DependencyData
		if dep == nil && rc != nil {
			dep = rc.DependencyData
		}
		if dep != nil {
			direct := dep.DirectDependency
			f.Direct, f.Parents = &direct, dep.ParentComponentPurls
		}
		if f.Identifier != nil {
			f.Format = f.Identifier.Format
		}
		f.Name, f.Version = purlName(f.PURL), purlVersion(f.PURL)
		if f.Name == "" {
			f.Name = firstNonEmpty(pc.DisplayName, pc.Hash)
		}
		if f.Version == "" {
			f.Version = f.Identifier.Version()
		}
		if f.Format == "" {
			f.Format = purlType(f.PURL)
		}
		// CVEs named by the violations, enriched with the raw report's data.
		issues := map[string]iq.SecurityIssue{}
		if rc != nil && rc.SecurityData != nil {
			for _, is := range rc.SecurityData.SecurityIssues {
				issues[is.Reference] = is
			}
		}
		seen := map[string]bool{}
		for _, v := range sec {
			if v.Waived && active {
				continue
			}
			f.ThreatLevel = max(f.ThreatLevel, v.PolicyThreatLevel)
			if !contains(f.Policies, v.PolicyName) {
				f.Policies = append(f.Policies, v.PolicyName)
			}
			for _, con := range v.Constraints {
				for _, cond := range con.Conditions {
					m := vulnReason.FindStringSubmatch(cond.ConditionReason)
					if m == nil || seen[m[1]] {
						continue
					}
					seen[m[1]] = true
					sev, _ := strconv.ParseFloat(m[2], 64)
					x := cve{ID: m[1], Severity: sev}
					if is, ok := issues[m[1]]; ok {
						x.Severity, x.ThreatCategory, x.Status, x.URL = is.Severity, is.ThreatCategory, is.Status, is.URL
					}
					f.CVEs = append(f.CVEs, x)
				}
			}
		}
		if len(f.CVEs) == 0 { // conditions without a parseable reason: list what the raw report has
			for _, is := range issues {
				if !strings.EqualFold(is.Status, "Not Applicable") {
					f.CVEs = append(f.CVEs, cve{ID: is.Reference, Severity: is.Severity, ThreatCategory: is.ThreatCategory, Status: is.Status, URL: is.URL})
				}
			}
		}
		sort.Slice(f.CVEs, func(i, j int) bool {
			if f.CVEs[i].Severity != f.CVEs[j].Severity {
				return f.CVEs[i].Severity > f.CVEs[j].Severity
			}
			return f.CVEs[i].ID < f.CVEs[j].ID
		})
		s.findings = append(s.findings, f)
	}
	sort.SliceStable(s.findings, func(i, j int) bool {
		a, b := s.findings[i], s.findings[j]
		if a.ThreatLevel != b.ThreatLevel {
			return a.ThreatLevel > b.ThreatLevel
		}
		return a.Name < b.Name
	})
	return s, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// purl helpers. "pkg:maven/g/a@1.0?type=jar" → type "maven", base
// "pkg:maven/g/a", name "g:a", version "1.0".
func purlSplit(p string) (typ, path, version string) {
	p = strings.TrimPrefix(p, "pkg:")
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	typ, path, _ = strings.Cut(p, "/")
	if i := strings.LastIndex(path, "@"); i > 0 {
		path, version = path[:i], path[i+1:]
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	return typ, path, version
}

func purlType(p string) string    { t, _, _ := purlSplit(p); return t }
func purlVersion(p string) string { _, _, v := purlSplit(p); return v }
func purlBase(p string) string    { t, path, _ := purlSplit(p); return "pkg:" + t + "/" + path }
func purlWithoutQualifiers(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

func purlName(p string) string {
	if p == "" {
		return ""
	}
	t, path, _ := purlSplit(p)
	if n, err := url.PathUnescape(path); err == nil {
		path = n
	}
	if t == "maven" {
		return strings.ReplaceAll(path, "/", ":")
	}
	return path
}

// matches reports whether a component argument (purl with or without
// version/qualifiers, or name) selects the finding.
func (f *finding) matches(arg string) bool {
	if strings.HasPrefix(arg, "pkg:") {
		if purlType(arg) != purlType(f.PURL) {
			return false
		}
		if purlVersion(arg) == "" {
			return purlBase(arg) == purlBase(f.PURL)
		}
		return purlWithoutQualifiers(arg) == purlWithoutQualifiers(f.PURL)
	}
	name, version, _ := strings.Cut(arg, "@")
	return strings.EqualFold(name, f.Name) && (version == "" || version == f.Version)
}

func isVulnID(s string) bool {
	u := strings.ToUpper(s)
	return strings.HasPrefix(u, "CVE-") || strings.HasPrefix(u, "SONATYPE-") || strings.HasPrefix(u, "GHSA-")
}

func (f *finding) hasCVE(id string) bool {
	for _, c := range f.CVEs {
		if strings.EqualFold(c.ID, id) {
			return true
		}
	}
	return false
}

var findingFields = []string{"application", "componentIdentifier", "cves", "dependency", "direct", "format", "hash", "name", "parents", "policies", "purl", "reportUrl", "stage", "threatLevel", "version", "waived"}

func findingJSON(s *scan, f *finding, fields []string) map[string]any {
	parents := f.Parents
	if parents == nil {
		parents = []string{}
	}
	cves := f.CVEs
	if cves == nil {
		cves = []cve{}
	}
	return pick(map[string]any{
		"application": s.app.PublicID, "componentIdentifier": f.Identifier, "cves": cves, "dependency": f.dependency(),
		"direct": f.Direct, "format": f.Format, "hash": f.Hash, "name": f.Name, "parents": parents, "policies": f.Policies,
		"purl": f.PURL, "reportUrl": s.reportURL, "stage": s.report.Stage, "threatLevel": f.ThreatLevel, "version": f.Version,
		"waived": f.Waived,
	}, fields)
}

func threatColor(level int, s string) string {
	switch {
	case level >= 8:
		return red(s)
	case level >= 4:
		return yellow(s)
	}
	return gray(s)
}

func newVulnListCmd() *cobra.Command {
	var appFlag, stage, cveFilter string
	var minThreat, limit int
	var direct, transitive, includeWaived bool
	var exp exporter
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List components with security policy violations",
		Long: `List the components of an application that violate a security policy in its
latest report, highest threat level first. One row per component, with the
vulnerabilities (CVE or sonatype-* IDs) that cause the violations.

The application comes from -A, ST_APP, or the IQ application whose source
control repository URL matches a git remote of the current checkout. The
report is the build stage's by default (else the most recent); see --stage.

Waived violations are left out unless --include-waived.

"dependency" is direct, transitive or unknown (IQ didn't report it);
"parents" are the direct dependencies that pull a transitive one in.`,
		Example: `  $ st vuln list
  $ st vuln list --min-threat 8 --direct
  $ st vuln list -A my-service --stage release --json name,version,cves --jq '.[].name'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if direct && transitive {
				return usageErr("--direct and --transitive are mutually exclusive")
			}
			c, err := clientFor("")
			if err != nil {
				return err
			}
			app, err := resolveApp(c, appFlag)
			if err != nil {
				return err
			}
			s, err := loadScan(c, app, stage, includeWaived)
			if err != nil {
				return err
			}
			var rows []*finding
			for i := range s.findings {
				f := &s.findings[i]
				switch {
				case f.ThreatLevel < minThreat,
					direct && f.dependency() != "direct",
					transitive && f.dependency() != "transitive",
					cveFilter != "" && !f.hasCVE(cveFilter):
					continue
				}
				rows = append(rows, f)
				if limit > 0 && len(rows) >= limit {
					break
				}
			}
			if exp.enabled() {
				out := []map[string]any{}
				for _, f := range rows {
					out = append(out, findingJSON(s, f, exp.fields))
				}
				return exp.write(stdout, out)
			}
			printFindings(stdout, s, rows)
			return nil
		},
	}
	addAppFlag(cmd, &appFlag)
	stageFlag(cmd, &stage)
	cmd.Flags().IntVar(&minThreat, "min-threat", 0, "Only components with a threat level of at least `N` (0-10)")
	cmd.Flags().BoolVar(&direct, "direct", false, "Only direct dependencies")
	cmd.Flags().BoolVar(&transitive, "transitive", false, "Only transitive dependencies")
	cmd.Flags().StringVar(&cveFilter, "cve", "", "Only components affected by vulnerability `ID`")
	cmd.Flags().BoolVar(&includeWaived, "include-waived", false, "Include components whose violations are all waived")
	cmd.Flags().IntVarP(&limit, "limit", "L", 0, "Maximum number of components to list")
	addJSONFlags(cmd, &exp, findingFields)
	return cmd
}

func printFindings(w io.Writer, s *scan, rows []*finding) {
	if !isTTY() {
		for _, f := range rows {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", f.ThreatLevel, f.PURL, f.dependency(), strings.Join(f.cveIDs(), ","), strings.Join(f.Policies, ","))
		}
		return
	}
	fmt.Fprintf(w, "\nShowing %d vulnerable components in %s (%s, evaluated %s)\n\n", len(rows), s.app.PublicID, s.report.Stage, ago(s.report.EvaluationDate))
	if len(rows) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "THREAT\tCOMPONENT\tVERSION\tDEPENDENCY\tVULNERABILITIES")
	for _, f := range rows {
		ids := f.cveIDs()
		more := ""
		if len(ids) > 3 {
			ids, more = ids[:3], fmt.Sprintf(" +%d", len(f.CVEs)-3)
		}
		dep := f.dependency()
		if f.Waived {
			dep += " (waived)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", threatColor(f.ThreatLevel, strconv.Itoa(f.ThreatLevel)), truncate(f.Name, 50), f.Version, gray(dep), strings.Join(ids, " ")+gray(more))
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%s\n", gray(s.reportURL))
}

var vulnFields = []string{"advisories", "categories", "cwes", "description", "detection", "detectionType", "explanation", "id", "kev", "link", "recommendation", "researchType", "rootCauses", "score", "severityScores", "source", "vector", "vulnIds", "vulnerableVersionRanges"}

func vulnJSON(v *iq.Vulnerability, fields []string) map[string]any {
	m := map[string]any{
		"advisories": v.Advisories, "categories": v.Categories, "description": v.Description, "detection": v.DetectionMarkdown,
		"detectionType": v.DetectionType, "explanation": v.ExplanationMarkdown, "id": v.Identifier, "link": v.VulnerabilityLink,
		"recommendation": v.RecommendationMarkdown, "researchType": v.ResearchType, "rootCauses": v.RootCauses,
		"severityScores": v.SeverityScores, "vulnIds": v.VulnIDs, "vulnerableVersionRanges": v.VulnerableVersionRanges,
		"cwes": []string{}, "kev": false, "score": nil, "vector": "", "source": "",
	}
	if v.Weakness != nil {
		var ids []string
		for _, c := range v.Weakness.CWEIDs {
			ids = append(ids, "CWE-"+strings.TrimPrefix(c.ID, "CWE-"))
		}
		m["cwes"] = ids
	}
	if v.KEVData != nil {
		m["kev"] = v.KEVData.IsKEV
	}
	if v.MainSeverity != nil {
		m["score"], m["vector"] = v.MainSeverity.Score, v.MainSeverity.Vector
	}
	if v.Source != nil {
		m["source"] = v.Source.ShortName
	}
	return pick(m, fields)
}

func newVulnViewCmd() *cobra.Command {
	var exp exporter
	cmd := &cobra.Command{
		Use:   "view <id>",
		Short: "View a vulnerability",
		Long: `Show a vulnerability by CVE or Sonatype ID: severity, CWE, whether it is
known to be exploited (CISA KEV), the vulnerable version ranges, and
Sonatype's description, explanation and recommendation.`,
		Example: `  $ st vuln view CVE-2022-42003
  $ st vuln view sonatype-2021-4682 --json vulnerableVersionRanges,recommendation`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := clientFor("")
			if err != nil {
				return err
			}
			v, err := c.Vulnerability(args[0])
			if err != nil {
				return err
			}
			if exp.enabled() {
				return exp.write(stdout, vulnJSON(v, exp.fields))
			}
			printVuln(stdout, v)
			return nil
		},
	}
	addJSONFlags(cmd, &exp, vulnFields)
	return cmd
}

func printVuln(w io.Writer, v *iq.Vulnerability) {
	m := vulnJSON(v, vulnFields)
	fmt.Fprintln(w, bold(firstNonEmpty(v.Identifier, "(redacted)")))
	if v.MainSeverity != nil {
		lvl := int(v.MainSeverity.Score + 0.5)
		fmt.Fprintf(w, "Severity:   %s %s\n", threatColor(lvl, strconv.FormatFloat(v.MainSeverity.Score, 'f', 1, 64)), gray(v.MainSeverity.Vector))
	}
	if cwes := m["cwes"].([]string); len(cwes) > 0 {
		fmt.Fprintf(w, "Weakness:   %s\n", strings.Join(cwes, ", "))
	}
	if m["kev"] == true {
		fmt.Fprintf(w, "Exploited:  %s\n", red("yes — listed in CISA KEV"))
	}
	if len(v.VulnerableVersionRanges) > 0 {
		fmt.Fprintf(w, "Vulnerable: %s\n", strings.Join(v.VulnerableVersionRanges, " "))
	}
	if v.VulnerabilityLink != "" {
		fmt.Fprintf(w, "Link:       %s\n", v.VulnerabilityLink)
	}
	for _, sec := range []struct{ title, body string }{
		{"Description", v.Description}, {"Explanation", v.ExplanationMarkdown},
		{"Detection", v.DetectionMarkdown}, {"Recommendation", v.RecommendationMarkdown},
	} {
		if strings.TrimSpace(sec.body) != "" {
			fmt.Fprintf(w, "\n%s\n%s\n", bold(sec.title), strings.TrimSpace(sec.body))
		}
	}
	if len(v.RootCauses) > 0 {
		fmt.Fprintf(w, "\n%s\n", bold("Root causes"))
		for _, rc := range v.RootCauses {
			fmt.Fprintf(w, "  %s  %s\n", rc.VersionRange, strings.Join(rc.ListOfPaths, " › "))
		}
	}
	if len(v.Advisories) > 0 {
		fmt.Fprintf(w, "\n%s\n", bold("Advisories"))
		for _, a := range v.Advisories {
			fmt.Fprintf(w, "  %s  %s\n", gray(strings.ToLower(a.ReferenceType)), a.URL)
		}
	}
}
