package cmd

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marcowarnke/st/internal/iq"
)

func newAppCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "app <command>",
		Aliases: []string{"application"},
		Short:   "List and view IQ applications",
	}
	cmd.AddCommand(newAppListCmd(), newAppViewCmd())
	return cmd
}

var appFields = []string{"id", "name", "organizationId", "publicId"}

func newAppListCmd() *cobra.Command {
	var search string
	var exp exporter
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List applications",
		Example: `  $ st app list
  $ st app list -S payments --json publicId --jq '.[].publicId'`,
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
			sort.Slice(apps, func(i, j int) bool { return apps[i].PublicID < apps[j].PublicID })
			var rows []iq.Application
			for _, a := range apps {
				if search == "" || strings.Contains(strings.ToLower(a.PublicID+" "+a.Name), strings.ToLower(search)) {
					rows = append(rows, a)
				}
			}
			if exp.enabled() {
				out := []map[string]any{}
				for _, a := range rows {
					out = append(out, pick(map[string]any{"id": a.ID, "name": a.Name, "organizationId": a.OrganizationID, "publicId": a.PublicID}, exp.fields))
				}
				return exp.write(stdout, out)
			}
			if !isTTY() {
				for _, a := range rows {
					fmt.Fprintf(stdout, "%s\t%s\t%s\n", a.PublicID, a.Name, a.ID)
				}
				return nil
			}
			tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "PUBLIC ID\tNAME")
			for _, a := range rows {
				fmt.Fprintf(tw, "%s\t%s\n", cyan(a.PublicID), a.Name)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVarP(&search, "search", "S", "", "Filter by public ID or name")
	addJSONFlags(cmd, &exp, appFields)
	return cmd
}

var appViewFields = []string{"baseBranch", "id", "name", "organizationId", "publicId", "reports", "repositoryUrl"}

func newAppViewCmd() *cobra.Command {
	var web bool
	var exp exporter
	cmd := &cobra.Command{
		Use:   "view [<public-id>]",
		Short: "View an application, its repository and latest reports",
		Long: `Show an application, its source control repository and its latest report
per stage. Without an argument, the application of the current checkout
(ST_APP, or matched from the git remote).`,
		Example: `  $ st app view
  $ st app view my-service --json reports --jq '.reports[] | select(.stage=="build").reportUrl'`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeApps,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := clientFor("")
			if err != nil {
				return err
			}
			arg := ""
			if len(args) == 1 {
				arg = args[0]
			}
			app, err := resolveApp(c, arg)
			if err != nil {
				return err
			}
			reports, err := c.Reports(app.ID)
			if err != nil {
				return err
			}
			if web {
				if len(reports) == 0 {
					return fmt.Errorf("application %s has no reports yet", app.PublicID)
				}
				r := reports[0]
				for _, x := range reports {
					if x.Stage == "build" {
						r = x
					}
				}
				return openBrowser(c.absURL(r.LatestReportHTMLURL))
			}
			sc, err := c.SourceControl(app.ID)
			if err != nil {
				sc = nil // needs extra permissions on some servers; the rest is still useful
			}
			if sc == nil {
				sc = &iq.SourceControl{}
			}
			reps := []map[string]any{}
			for _, r := range reports {
				reps = append(reps, map[string]any{
					"stage": r.Stage, "evaluationDate": r.EvaluationDate, "reportId": r.ReportID(),
					"reportUrl": c.absURL(r.ReportHTMLURL), "latestReportUrl": c.absURL(r.LatestReportHTMLURL),
				})
			}
			if exp.enabled() {
				return exp.write(stdout, pick(map[string]any{
					"baseBranch": sc.BaseBranch, "id": app.ID, "name": app.Name, "organizationId": app.OrganizationID,
					"publicId": app.PublicID, "reports": reps, "repositoryUrl": sc.RepositoryURL,
				}, exp.fields))
			}
			fmt.Fprintf(stdout, "%s %s\n", bold(app.Name), gray("("+app.PublicID+")"))
			if sc.RepositoryURL != "" {
				fmt.Fprintf(stdout, "Repository: %s", sc.RepositoryURL)
				if sc.BaseBranch != "" {
					fmt.Fprintf(stdout, " (%s)", sc.BaseBranch)
				}
				fmt.Fprintln(stdout)
			}
			if len(reports) == 0 {
				fmt.Fprintln(stdout, "\nNo reports yet")
				return nil
			}
			fmt.Fprintln(stdout)
			tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "STAGE\tEVALUATED\tREPORT")
			for _, r := range reports {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Stage, ago(r.EvaluationDate), c.absURL(r.ReportHTMLURL))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVarP(&web, "web", "w", false, "Open the latest report in the browser")
	addJSONFlags(cmd, &exp, appViewFields)
	return cmd
}
