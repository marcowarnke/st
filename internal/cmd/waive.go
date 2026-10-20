package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marcowarnke/st/internal/iq"
)

// Waivers always expire: 7 days unless --expires says otherwise, at most 90.
const (
	defaultWaiverDays = 7
	maxWaiverDays     = 90
)

// now is swappable for tests.
var now = time.Now

// parseExpiry accepts "<N>d", "<N>w" or a date (YYYY-MM-DD, end of that day
// in local time) and returns when the waiver expires.
func parseExpiry(s string) (time.Time, error) {
	t0 := now()
	var exp time.Time
	switch {
	case strings.HasSuffix(s, "d") || strings.HasSuffix(s, "w"):
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil || n <= 0 {
			return time.Time{}, fmt.Errorf("invalid --expires %q: use e.g. 7d, 2w or a date (YYYY-MM-DD)", s)
		}
		if strings.HasSuffix(s, "w") {
			n *= 7
		}
		exp = t0.AddDate(0, 0, n)
	default:
		d, err := time.ParseInLocation("2006-01-02", s, t0.Location())
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid --expires %q: use e.g. 7d, 2w or a date (YYYY-MM-DD)", s)
		}
		exp = d.Add(24*time.Hour - time.Millisecond)
	}
	if !exp.After(t0) {
		return time.Time{}, fmt.Errorf("--expires %s is in the past", s)
	}
	if exp.After(t0.AddDate(0, 0, maxWaiverDays)) {
		return time.Time{}, fmt.Errorf("--expires %s is too far out: waivers expire within %d days at most", s, maxWaiverDays)
	}
	return exp, nil
}

func newWaiveCmd() *cobra.Command {
	var appFlag, stage, comment, expires, policy string
	var allVersions, dryRun bool
	var exp exporter
	cmd := &cobra.Command{
		Use:   "waive <purl> | <name>",
		Short: "Waive a component's security policy violations for a limited time",
		Long: `Create IQ Server waivers for the unwaived security policy violations of one
component in the application. This is the only st command that changes
anything on the server.

Only waive when a person has decided to accept the risk (false positive,
vulnerable code not reachable, fix scheduled); prefer an upgrade (st fix).
Agents: never waive on your own initiative.

--comment is required and is stored with the waiver: say why the risk is
accepted. Waivers always expire: after 7 days by default, at most 90 days
(--expires 30d, 4w or a date). They cover this version of the component
only, unless --all-versions.

The component is a package URL (with or without version) or a name
("group:artifact" for Maven, the package name elsewhere), and must select
exactly one component. --policy restricts it to one policy's violation.
--dry-run shows what would be waived.

Needs the "Waive Policy Violations" permission in IQ Server.`,
		Example: `  $ st waive pkg:maven/org.yaml/snakeyaml@1.26 --comment "SafeConstructor only; untrusted YAML never parsed" --dry-run
  $ st waive lodash --comment "Fix ships in PR #42" --expires 14d
  $ st waive com.fasterxml.jackson.core:jackson-databind --policy Security-High --comment "…" --json violationId,expiresAt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			comment = strings.TrimSpace(comment)
			if comment == "" {
				return usageErr("--comment is required: say why the risk is accepted")
			}
			expiry, err := parseExpiry(expires)
			if err != nil {
				return err
			}
			scope := iq.WaiveExactComponent
			if allVersions {
				scope = iq.WaiveAllVersions
			}
			c, err := clientFor("")
			if err != nil {
				return err
			}
			app, err := resolveApp(c, appFlag)
			if err != nil {
				return err
			}
			s, err := loadScan(c, app, stage, false)
			if err != nil {
				return err
			}
			var matched []*finding
			for i := range s.findings {
				if s.findings[i].matches(args[0]) {
					matched = append(matched, &s.findings[i])
				}
			}
			switch {
			case len(matched) == 0:
				return fmt.Errorf("%s has no unwaived security violations in %s's %s report", args[0], app.PublicID, s.report.Stage)
			case len(matched) > 1:
				var purls []string
				for _, f := range matched {
					purls = append(purls, f.PURL)
				}
				return fmt.Errorf("%s matches %d components; pass the package URL of one:\n  %s", args[0], len(matched), strings.Join(purls, "\n  "))
			}
			f := matched[0]
			var vs []violationRef
			for _, v := range f.Violations {
				if policy == "" || strings.EqualFold(v.Policy, policy) {
					vs = append(vs, v)
				}
			}
			if len(vs) == 0 {
				return fmt.Errorf("%s has no unwaived %s violation", f.Name, policy)
			}
			for _, v := range vs {
				if v.ID == "" {
					return fmt.Errorf("IQ Server reported no policy violation ID for %s; this IQ version may not support waivers over the API", f.Name)
				}
			}
			req := iq.WaiverRequest{Comment: comment, ExpiryTime: expiry.Format(iq.WaiverTimeLayout), MatcherStrategy: scope}
			out := []map[string]any{}
			var created []string
			for _, v := range vs {
				if !dryRun {
					if err := c.CreateWaiver(app.ID, v.ID, req); err != nil {
						err = fmt.Errorf("waiving %s violation of %s: %w", v.Policy, f.Name, err)
						if len(created) == 0 {
							return err
						}
						// Earlier waivers exist now; report them so they aren't created twice.
						if exp.enabled() {
							_ = exp.write(stdout, out)
						}
						return fmt.Errorf("%w\n%d of %d waivers were created before this failure (%s); don't create them again",
							err, len(created), len(vs), strings.Join(created, ", "))
					}
					created = append(created, v.Policy)
				}
				if exp.enabled() {
					out = append(out, pick(map[string]any{
						"application": app.PublicID, "component": f.PURL, "violationId": v.ID, "policy": v.Policy,
						"threatLevel": v.ThreatLevel, "scope": scope, "expiresAt": req.ExpiryTime, "comment": comment, "dryRun": dryRun,
					}, exp.fields))
					continue
				}
				verb := "Waived"
				if dryRun {
					verb = "Would waive"
				}
				what := f.Name + "@" + f.Version
				if allVersions {
					what = f.Name + " (all versions)"
				}
				success("%s %s violation (threat %d) of %s in %s until %s", verb, v.Policy, v.ThreatLevel, what, app.PublicID, expiry.Format("2006-01-02"))
			}
			if exp.enabled() {
				return exp.write(stdout, out)
			}
			return nil
		},
	}
	addAppFlag(cmd, &appFlag)
	stageFlag(cmd, &stage)
	cmd.Flags().StringVarP(&comment, "comment", "m", "", "Why the risk is accepted (required)")
	cmd.Flags().StringVar(&expires, "expires", strconv.Itoa(defaultWaiverDays)+"d", fmt.Sprintf("When the waiver expires: `<N>d`, <N>w or YYYY-MM-DD (at most %d days)", maxWaiverDays))
	cmd.Flags().StringVar(&policy, "policy", "", "Only waive this policy's violation")
	cmd.Flags().BoolVar(&allVersions, "all-versions", false, "Waive for every version of the component, not just this one")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be waived without changing anything")
	addJSONFlags(cmd, &exp, []string{"application", "comment", "component", "dryRun", "expiresAt", "policy", "scope", "threatLevel", "violationId"})
	return cmd
}
