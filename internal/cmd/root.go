// Package cmd implements the st command tree, following gh's (and bb's) UX.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marcowarnke/st/internal/config"
	"github.com/marcowarnke/st/internal/iq"
)

var Version = "dev"

// IO is swappable for tests.
var (
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
	isTTY            = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }
)

// Exit codes: 1 error, 4 auth, 9 no remediation for some components.
const (
	exitAuth          = 4
	exitNoRemediation = 9
)

// ExitError carries a specific exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "st <command> <subcommand> [flags]",
		Short: "Sonatype IQ Server CLI",
		Long: `Find vulnerable dependencies in Sonatype IQ Server (Lifecycle) and the
versions that fix them, from the command line.

Built for agents: output is plain when piped, --json/--jq everywhere, and
the target application is resolved from the git remote of the checkout.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Example: `  $ st vuln list
  $ st vuln view CVE-2022-42003
  $ st fix --json purl,target,strategy,parents
  $ st status`,
	}
	root.SetFlagErrorFunc(flagError)
	root.AddCommand(newAuthCmd(), newAppCmd(), newVulnCmd(), newFixCmd(), newWaiveCmd(), newStatusCmd(), newAPICmd(), newSkillsCmd())
	return root
}

// osArgs overrides os.Args[1:] in tests.
var osArgs []string

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	root := NewRoot()
	if osArgs != nil {
		root.SetArgs(osArgs)
	}
	err := root.Execute()
	if err == nil {
		return 0
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		if ee.Err != nil {
			fmt.Fprintln(stderr, ee.Err)
		}
		return ee.Code
	}
	fmt.Fprintln(stderr, err)
	var api *iq.APIError
	if errors.As(err, &api) && api.StatusCode == 401 || errors.Is(err, config.ErrNoHost) {
		return exitAuth
	}
	if hint := errorHint(err); hint != "" {
		fmt.Fprintln(stderr, hint)
	}
	return 1
}

// errorHint suggests a next step for API errors that are not self-explanatory.
func errorHint(err error) string {
	var api *iq.APIError
	if !errors.As(err, &api) {
		return ""
	}
	switch {
	case api.StatusCode == 403:
		return "hint: the user lacks permission for this request in IQ Server; ask an IQ administrator"
	case api.StatusCode == 404:
		return "hint: IQ Server has no such resource, or the endpoint does not exist in this IQ version. " +
			"Check the application and its reports with `st app view`; rerun with ST_DEBUG=1 to see every request"
	case api.StatusCode == 429 || api.StatusCode >= 500:
		return "hint: IQ Server is overloaded or failing; try again later, or narrow the request (e.g. `st status -S text`)"
	}
	return ""
}

// flagError mirrors gh: `--json` without a value lists the available fields.
func flagError(c *cobra.Command, err error) error {
	if strings.Contains(err.Error(), "flag needs an argument: --json") {
		if f := c.Flags().Lookup("json"); f != nil {
			if fields, ok := f.Annotations["fields"]; ok {
				return fmt.Errorf("Specify one or more comma-separated fields for `--json`:\n  %s", strings.Join(fields, "\n  "))
			}
		}
	}
	return err
}

func usageErr(format string, a ...any) error {
	return fmt.Errorf(format, a...)
}

func success(format string, a ...any) {
	mark := "✓"
	if isTTY() {
		mark = green(mark)
	}
	fmt.Fprintf(stderr, mark+" "+format+"\n", a...)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
