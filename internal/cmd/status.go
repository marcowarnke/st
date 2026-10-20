package cmd

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marcowarnke/st/internal/iq"
)

type appStatus struct {
	app  iq.Application
	scan *scan
	err  error
}

func newStatusCmd() *cobra.Command {
	var stage, search string
	var minThreat int
	var exp exporter
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Security dashboard across all applications",
		Long: `For every application you can see, count the components with unwaived
security violations in its latest report (build by default), and the
highest threat level. Applications with findings come first.

This reads the report list and the policy report of each application
(two requests per application); narrow it with -S.`,
		Example: `  $ st status
  $ st status --min-threat 8 --json application,threatLevel,components`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := clientFor("")
			if err != nil {
				return err
			}
			apps, err := c.Applications()
			if err != nil {
				return err
			}
			var sts []*appStatus
			for _, a := range apps {
				if search == "" || strings.Contains(strings.ToLower(a.PublicID+" "+a.Name), strings.ToLower(search)) {
					sts = append(sts, &appStatus{app: a})
				}
			}
			sem := make(chan struct{}, 8)
			var wg sync.WaitGroup
			for _, st := range sts {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer func() { <-sem; wg.Done() }()
					st.scan, st.err = loadScanWith(c, &st.app, stage, false, false)
				}()
			}
			wg.Wait()
			for _, st := range sts {
				var api *iq.APIError
				if errors.As(st.err, &api) && api.StatusCode == 401 {
					return st.err
				}
			}
			threat := func(st *appStatus) int {
				if st.scan == nil || len(st.scan.findings) == 0 {
					return -1
				}
				return st.scan.findings[0].ThreatLevel
			}
			count := func(st *appStatus) (n, direct int) {
				if st.scan == nil {
					return 0, 0
				}
				for _, f := range st.scan.findings {
					if f.ThreatLevel >= minThreat {
						n++
						if f.dependency() == "direct" {
							direct++
						}
					}
				}
				return
			}
			sort.SliceStable(sts, func(i, j int) bool {
				if a, b := threat(sts[i]), threat(sts[j]); a != b {
					return a > b
				}
				return sts[i].app.PublicID < sts[j].app.PublicID
			})
			if exp.enabled() {
				out := []map[string]any{}
				for _, st := range sts {
					n, d := count(st)
					m := map[string]any{"application": st.app.PublicID, "name": st.app.Name, "components": n, "direct": d,
						"threatLevel": max(threat(st), 0), "stage": "", "evaluationDate": "", "reportUrl": "", "error": ""}
					if st.scan != nil {
						m["stage"], m["evaluationDate"], m["reportUrl"] = st.scan.report.Stage, st.scan.report.EvaluationDate, st.scan.reportURL
					}
					if st.err != nil {
						m["error"] = st.err.Error()
					}
					out = append(out, pick(m, exp.fields))
				}
				return exp.write(stdout, out)
			}
			tty := isTTY()
			tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			if tty {
				fmt.Fprintln(tw, "APPLICATION\tTHREAT\tCOMPONENTS\tDIRECT\tSTAGE\tEVALUATED")
			}
			for _, st := range sts {
				n, d := count(st)
				if st.err != nil {
					if tty {
						fmt.Fprintf(tw, "%s\t\t\t\t\t%s\n", st.app.PublicID, gray(truncate(st.err.Error(), 70)))
					} else {
						fmt.Fprintf(stdout, "%s\t\t\t\t\terror: %s\n", st.app.PublicID, st.err)
					}
					continue
				}
				lvl := strconv.Itoa(max(threat(st), 0))
				if !tty {
					fmt.Fprintf(stdout, "%s\t%s\t%d\t%d\t%s\t%s\n", st.app.PublicID, lvl, n, d, st.scan.report.Stage, st.scan.report.EvaluationDate)
					continue
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n", cyan(st.app.PublicID), threatColor(threat(st), lvl), n, d, st.scan.report.Stage, gray(ago(st.scan.report.EvaluationDate)))
			}
			return tw.Flush()
		},
	}
	stageFlag(cmd, &stage)
	cmd.Flags().StringVarP(&search, "search", "S", "", "Only applications whose public ID or name contains `text`")
	cmd.Flags().IntVar(&minThreat, "min-threat", 0, "Only count components with a threat level of at least `N`")
	addJSONFlags(cmd, &exp, []string{"application", "components", "direct", "error", "evaluationDate", "name", "reportUrl", "stage", "threatLevel"})
	return cmd
}
