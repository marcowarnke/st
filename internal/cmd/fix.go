package cmd

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marcowarnke/st/internal/iq"
)

// strategies in order of preference. Golden versions first (no violations,
// no breaking API changes), then the nearest version without violations,
// then the nearest one that merely stops failing the stage. The
// "-with-dependencies" variants also require the version's own dependencies
// to be clean.
var strategies = []string{
	"recommended-non-breaking-with-dependencies",
	"recommended-non-breaking",
	"next-no-violations-with-dependencies",
	"next-no-violations",
	"next-non-failing-with-dependencies",
	"next-non-failing",
}

// complete reports whether a strategy clears every policy violation, not
// only the ones that fail the stage.
func complete(strategy string) bool { return !strings.HasPrefix(strategy, "next-non-failing") }

type parentFix struct {
	Name       string `json:"name"`
	PURL       string `json:"purl"`
	Current    string `json:"current"`
	Target     string `json:"target"`
	TargetPURL string `json:"targetPurl"`
}

type fix struct {
	f          *finding
	Available  bool
	Strategy   string
	Target     string
	TargetPURL string
	Direct     *bool
	Parents    []parentFix
	Breaking   *bool
	Err        string
}

// remediate asks IQ for version changes and picks the preferred one.
func remediate(c *session, s *scan, f *finding, prefer []string) (*fix, error) {
	x := &fix{f: f, Direct: f.Direct}
	if f.Identifier == nil {
		x.Err = "IQ Server reported no component identifier for this component"
		return x, nil
	}
	changes, err := c.Remediation(s.app.ID, s.report.Stage, f.Identifier)
	if err != nil {
		var api *iq.APIError
		if errors.As(err, &api) && (api.StatusCode == 401 || api.StatusCode == 403) {
			return nil, err
		}
		x.Err = err.Error()
		return x, nil
	}
	byType := map[string]*iq.VersionChange{}
	for i := range changes {
		ch := &changes[i]
		v := ch.Data.Component.ComponentIdentifier.Version()
		if v == "" {
			v = purlVersion(ch.Data.Component.PackageURL)
		}
		if v == "" || v == f.Version || byType[ch.Type] != nil {
			continue // IQ returns the current version when it already satisfies the strategy
		}
		byType[ch.Type] = ch
	}
	for _, st := range prefer {
		ch := byType[st]
		if ch == nil {
			continue
		}
		x.Available, x.Strategy = true, st
		x.TargetPURL = ch.Data.Component.PackageURL
		x.Target = firstNonEmpty(ch.Data.Component.ComponentIdentifier.Version(), purlVersion(x.TargetPURL))
		if ch.DirectDependency != nil {
			d := *ch.DirectDependency
			x.Direct = &d
		}
		for _, dd := range ch.DirectDependencyData {
			p := parentFix{TargetPURL: dd.Component.PackageURL, Name: purlName(dd.Component.PackageURL)}
			p.Target = firstNonEmpty(dd.Component.ComponentIdentifier.Version(), purlVersion(p.TargetPURL))
			for _, cur := range f.Parents {
				if purlBase(cur) == purlBase(p.TargetPURL) {
					p.PURL, p.Current = cur, purlVersion(cur)
				}
			}
			x.Parents = append(x.Parents, p)
		}
		break
	}
	if len(x.Parents) == 0 && x.Direct != nil && !*x.Direct {
		for _, cur := range f.Parents {
			x.Parents = append(x.Parents, parentFix{Name: purlName(cur), PURL: cur, Current: purlVersion(cur)})
		}
	}
	if x.Available {
		x.Breaking = breaking(x)
	}
	return x, nil
}

// breaking: false for golden versions, else whether the major version of
// what gets bumped changes; nil if versions aren't numeric.
func breaking(x *fix) *bool {
	no, yes := false, true
	if strings.HasPrefix(x.Strategy, "recommended-non-breaking") {
		return &no
	}
	cur, tgt := x.f.Version, x.Target
	for _, p := range x.Parents {
		if p.Target != "" && p.Current != "" {
			cur, tgt = p.Current, p.Target
			break
		}
	}
	a, okA := major(cur)
	b, okB := major(tgt)
	if !okA || !okB {
		return nil
	}
	if a != b || a == 0 && minor(cur) != minor(tgt) {
		return &yes // 0.x minors break by convention
	}
	return &no
}

// versionPart returns the i-th numeric dot-separated part of a version.
func versionPart(v string, i int) (int, bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V"), ".")
	if i >= len(parts) {
		return 0, false
	}
	p := parts[i]
	if end := strings.IndexFunc(p, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
		p = p[:end]
	}
	n, err := strconv.Atoi(p)
	return n, err == nil
}

func major(v string) (int, bool) { return versionPart(v, 0) }
func minor(v string) int         { n, _ := versionPart(v, 1); return n }

// manifestHint tells the agent where the change goes for the ecosystem.
func manifestHint(x *fix) string {
	f := x.f
	transitive := x.Direct != nil && !*x.Direct
	parentKnown := false
	for _, p := range x.Parents {
		parentKnown = parentKnown || p.Target != ""
	}
	if transitive && parentKnown {
		return "transitive: bump the parent dependency listed in parents to its target version"
	}
	name := f.Name
	switch f.Format {
	case "maven":
		if transitive {
			return fmt.Sprintf("transitive: find the path with `mvn dependency:tree -Dincludes=%s` or `gradle dependencyInsight --dependency %s`; bump the parent, or pin the version in <dependencyManagement> (Maven) / a constraints block (Gradle)", name, name[strings.LastIndex(name, ":")+1:])
		}
		return "pom.xml or build.gradle: update the version (it may be set by a property, a BOM or dependencyManagement)"
	case "npm":
		if transitive {
			return fmt.Sprintf("transitive: `npm why %s` shows the path; bump the parent, or add an \"overrides\" (npm) / \"resolutions\" (yarn) entry; then refresh the lockfile", name)
		}
		return "package.json: update the version range, then refresh the lockfile"
	case "golang":
		return fmt.Sprintf("`go get %s@v%s && go mod tidy`", name, strings.TrimPrefix(x.Target, "v"))
	case "pypi":
		if transitive {
			return fmt.Sprintf("transitive: `pipdeptree -r -p %s` shows the path; bump the parent or add a constraint", name)
		}
		return "requirements.txt / pyproject.toml: update the pinned version, then refresh the lockfile"
	case "nuget":
		if transitive {
			return "transitive: bump the parent, or add a direct <PackageReference> at the target version"
		}
		return "*.csproj / Directory.Packages.props: update the PackageReference version"
	}
	if transitive {
		return "transitive: bump the parent dependency or pin the version in the package manager's override mechanism"
	}
	return "update the dependency version in the manifest"
}

var fixFields = []string{"application", "available", "breaking", "complete", "current", "dependency", "direct", "error", "format", "manifestHint", "name", "parents", "purl", "reportUrl", "resolves", "stage", "strategy", "target", "targetPurl", "threatLevel"}

func fixJSON(s *scan, x *fix, fields []string) map[string]any {
	dep := "unknown"
	if x.Direct != nil {
		dep = map[bool]string{true: "direct", false: "transitive"}[*x.Direct]
	}
	parents := x.Parents
	if parents == nil {
		parents = []parentFix{}
	}
	resolves := x.f.CVEs
	if resolves == nil || !x.Available {
		resolves = []cve{}
	}
	return pick(map[string]any{
		"application": s.app.PublicID, "available": x.Available, "breaking": x.Breaking, "complete": x.Available && complete(x.Strategy),
		"current": x.f.Version, "dependency": dep, "direct": x.Direct, "error": x.Err, "format": x.f.Format,
		"manifestHint": manifestHint(x), "name": x.f.Name, "parents": parents, "purl": x.f.PURL, "reportUrl": s.reportURL,
		"resolves": resolves, "stage": s.report.Stage, "strategy": x.Strategy, "target": x.Target, "targetPurl": x.TargetPURL,
		"threatLevel": x.f.ThreatLevel,
	}, fields)
}

func newFixCmd() *cobra.Command {
	var appFlag, stage string
	var prefer []string
	var minThreat int
	var includeWaived bool
	var exp exporter
	cmd := &cobra.Command{
		Use:   "fix [<purl> | <name> | <vulnerability-id>]",
		Short: "Find the version upgrade that fixes vulnerable components",
		Long: `Ask IQ Server which version to upgrade each vulnerable component to, and say
how to apply it. st fix only reads; it never edits files.

Without arguments, every component with an (unwaived) security violation in
the latest report is covered. A package URL (with or without version), a
component name ("group:artifact" for Maven, the package name elsewhere), or
a vulnerability ID (CVE-…, sonatype-…) narrows it down.

The target version is IQ's remediation, preferring in this order:
  recommended-non-breaking-with-dependencies  golden version, deps clean too
  recommended-non-breaking                    golden version
  next-no-violations-with-dependencies        nearest clean version, deps clean too
  next-no-violations                          nearest version without violations
  next-non-failing-with-dependencies          nearest version that passes the stage
  next-non-failing                            (may leave non-failing violations)
--strategy changes the order or restricts it.

For transitive dependencies, "parents" names the direct dependency to bump
(and its target version, where IQ knows it: Maven). Otherwise manifestHint
says how to find the path or pin the version.

Fields: "complete" is false when the chosen strategy only stops the stage
failing; "breaking" is false for golden versions, true when the major
version of what you bump changes, null when unknown.

Exit status 9 when some components have no remediation (IQ knows no fixed
version, or the request failed: see "error").`,
		Example: `  $ st fix
  $ st fix pkg:maven/com.fasterxml.jackson.core/jackson-databind
  $ st fix CVE-2022-42003 --json name,current,target,strategy,parents,manifestHint
  $ st fix --strategy next-no-violations,next-non-failing`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, st := range prefer {
				if !contains(strategies, st) {
					return usageErr("invalid --strategy %q: valid values are\n  %s", st, strings.Join(strategies, "\n  "))
				}
			}
			if len(prefer) == 0 {
				prefer = strategies
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
			var targets []*finding
			for i := range s.findings {
				f := &s.findings[i]
				if f.ThreatLevel < minThreat {
					continue
				}
				if len(args) == 1 && !(isVulnID(args[0]) && f.hasCVE(args[0]) || !isVulnID(args[0]) && f.matches(args[0])) {
					continue
				}
				targets = append(targets, f)
			}
			if len(args) == 1 && len(targets) == 0 {
				return fmt.Errorf("%s has no security violations in %s's %s report", args[0], app.PublicID, s.report.Stage)
			}
			fixes := make([]*fix, len(targets))
			errs := make([]error, len(targets))
			sem := make(chan struct{}, 4)
			var wg sync.WaitGroup
			for i, f := range targets {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer func() { <-sem; wg.Done() }()
					fixes[i], errs[i] = remediate(c, s, f, prefer)
				}()
			}
			wg.Wait()
			if err := errors.Join(errs...); err != nil {
				return err
			}
			missing := 0
			for _, x := range fixes {
				if !x.Available {
					missing++
				}
			}
			if exp.enabled() {
				out := []map[string]any{}
				for _, x := range fixes {
					out = append(out, fixJSON(s, x, exp.fields))
				}
				if err := exp.write(stdout, out); err != nil {
					return err
				}
			} else {
				printFixes(stdout, s, fixes)
			}
			if missing > 0 {
				return &ExitError{Code: exitNoRemediation, Err: fmt.Errorf("%d of %d components have no remediation", missing, len(fixes))}
			}
			return nil
		},
	}
	addAppFlag(cmd, &appFlag)
	stageFlag(cmd, &stage)
	cmd.Flags().StringSliceVar(&prefer, "strategy", nil, "Remediation `strategies` to use, in order of preference")
	cmd.Flags().IntVar(&minThreat, "min-threat", 0, "Only components with a threat level of at least `N` (0-10)")
	cmd.Flags().BoolVar(&includeWaived, "include-waived", false, "Include components whose violations are all waived")
	_ = cmd.RegisterFlagCompletionFunc("strategy", cobra.FixedCompletions(strategies, cobra.ShellCompDirectiveNoFileComp))
	addJSONFlags(cmd, &exp, fixFields)
	return cmd
}

// how summarises what to change: the component itself, or a parent.
func (x *fix) how() string {
	if !x.Available {
		return "no remediation"
	}
	for _, p := range x.Parents {
		if p.Target != "" {
			return fmt.Sprintf("via %s %s → %s", p.Name, firstNonEmpty(p.Current, "?"), p.Target)
		}
	}
	if x.Direct != nil && !*x.Direct {
		return "transitive"
	}
	if x.Direct == nil {
		return "unknown"
	}
	return "direct"
}

func printFixes(w io.Writer, s *scan, fixes []*fix) {
	if !isTTY() {
		for _, x := range fixes {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", x.f.PURL, x.f.Version, x.Target, x.how(), x.Strategy, strings.Join(x.f.cveIDs(), ","))
		}
		return
	}
	fmt.Fprintf(w, "\nRemediation for %d components in %s (%s, evaluated %s)\n\n", len(fixes), s.app.PublicID, s.report.Stage, ago(s.report.EvaluationDate))
	if len(fixes) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "THREAT\tCOMPONENT\tUPGRADE\tHOW\tSTRATEGY")
	var notes []string
	for _, x := range fixes {
		upgrade := x.f.Version + " → " + firstNonEmpty(x.Target, "–")
		strategy := x.Strategy
		if x.Breaking != nil && *x.Breaking {
			strategy += yellow(" ⚠ major bump")
		}
		how := x.how()
		if !x.Available {
			how = red(how)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", threatColor(x.f.ThreatLevel, strconv.Itoa(x.f.ThreatLevel)), truncate(x.f.Name, 50), upgrade, how, strategy)
		switch {
		case x.Err != "":
			notes = append(notes, fmt.Sprintf("%s: %s", x.f.Name, x.Err))
		case x.Available && x.Direct != nil && !*x.Direct && !strings.HasPrefix(x.how(), "via"):
			notes = append(notes, fmt.Sprintf("%s: %s", x.f.Name, manifestHint(x)))
		}
	}
	tw.Flush()
	for _, n := range notes {
		fmt.Fprintf(w, "\n%s", gray(n))
	}
	if len(notes) > 0 {
		fmt.Fprintln(w)
	}
}
