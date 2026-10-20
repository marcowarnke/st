package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/marcowarnke/st/internal/config"
	"github.com/marcowarnke/st/internal/git"
	"github.com/marcowarnke/st/internal/iq"
)

// session is an authenticated client plus the host key it belongs to.
type session struct {
	*iq.Client
	host string
}

// absURL resolves the server-relative links IQ returns ("ui/links/…").
func (c *session) absURL(u string) string {
	if u == "" || strings.Contains(u, "://") {
		return u
	}
	return c.URL(u, nil)
}

func clientFor(host string) (*session, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	key, h, err := cfg.Resolve(host)
	if err != nil {
		return nil, &ExitError{Code: exitAuth, Err: err}
	}
	return &session{newIQ(h.BaseURL, h.User, h.Token), key}, nil
}

// newIQ creates a client; ST_DEBUG=1 logs every request to stderr.
func newIQ(baseURL, user, password string) *iq.Client {
	c := iq.New(baseURL, user, password)
	if os.Getenv("ST_DEBUG") != "" {
		c.Debug = stderr
	}
	return c
}

// addAppFlag registers -A/--app with completion of application public IDs.
func addAppFlag(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVarP(p, "app", "A", "", "Application public ID (default: ST_APP, else matched from the git remote)")
	_ = cmd.RegisterFlagCompletionFunc("app", completeApps)
}

func completeApps(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	c, err := clientFor("")
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	apps, err := c.Applications()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, a := range apps {
		out = append(out, a.PublicID+"\t"+a.Name)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// resolveApp picks the application: -A, ST_APP, then the IQ application
// whose source control repository URL matches a git remote of the checkout.
func resolveApp(c *session, flag string) (*iq.Application, error) {
	if flag == "" {
		flag = os.Getenv("ST_APP")
	}
	if flag != "" {
		return c.Application(flag)
	}
	remotes, _ := git.Remotes()
	var keys []string
	for _, r := range remotes {
		if k, ok := git.RepoKey(r.URL); ok && !contains(keys, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("not in a git repository with a remote; pass -A/--app PUBLIC_ID or set ST_APP")
	}
	cache := loadAppCache()
	for _, k := range keys {
		if id := cache[c.host][k]; id != "" {
			if app, err := c.Application(id); err == nil {
				return app, nil
			}
		}
	}
	byRepo, err := scanRepositories(c)
	if err != nil {
		return nil, err
	}
	known := map[string]string{}
	for k, ids := range byRepo {
		if len(ids) == 1 {
			known[k] = ids[0]
		}
	}
	cache[c.host] = known
	saveAppCache(cache)
	for _, k := range keys {
		switch ids := byRepo[k]; len(ids) {
		case 0:
			continue
		case 1:
			return c.Application(ids[0])
		default:
			sort.Strings(ids)
			return nil, fmt.Errorf("several applications use repository %s (%s); pass -A/--app", k, strings.Join(ids, ", "))
		}
	}
	return nil, fmt.Errorf("no IQ application has a repository URL matching %s; pass -A/--app PUBLIC_ID or set ST_APP", strings.Join(keys, ", "))
}

// scanRepositories maps repository keys to application public IDs by reading
// every application's source control configuration.
func scanRepositories(c *session) (map[string][]string, error) {
	apps, err := c.Applications()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, a := range apps {
		wg.Add(1)
		sem <- struct{}{}
		go func(a iq.Application) {
			defer func() { <-sem; wg.Done() }()
			sc, err := c.SourceControl(a.ID)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if sc == nil {
				return
			}
			if k, ok := git.RepoKey(sc.RepositoryURL); ok {
				out[k] = append(out[k], a.PublicID)
			}
		}(a)
	}
	wg.Wait()
	if firstErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("reading source control configuration: %w", firstErr)
	}
	return out, nil
}

// The repository → application map is cached per host in apps.json, since
// building it costs one request per application.
func appCachePath() string { return filepath.Join(config.Dir(), "apps.json") }

func loadAppCache() map[string]map[string]string {
	m := map[string]map[string]string{}
	if data, err := os.ReadFile(appCachePath()); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func saveAppCache(m map[string]map[string]string) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return
	}
	if os.MkdirAll(config.Dir(), 0o700) == nil {
		_ = os.WriteFile(appCachePath(), append(data, '\n'), 0o600)
	}
}

// pickReport selects the report for --stage; by default build, else the
// most recently evaluated stage.
func pickReport(c *session, app *iq.Application, stage string) (*iq.ReportInfo, error) {
	reports, err := c.Reports(app.ID)
	if err != nil {
		return nil, err
	}
	if len(reports) == 0 {
		return nil, fmt.Errorf("application %s has not been evaluated yet (no reports)", app.PublicID)
	}
	want := stage
	if want == "" {
		want = "build"
	}
	var stages []string
	for i := range reports {
		if reports[i].Stage == want {
			return &reports[i], nil
		}
		stages = append(stages, reports[i].Stage)
	}
	if stage != "" {
		return nil, fmt.Errorf("application %s has no %s report; available stages: %s", app.PublicID, stage, strings.Join(stages, ", "))
	}
	latest := &reports[0]
	for i := range reports {
		a, _ := parseTime(reports[i].EvaluationDate)
		b, _ := parseTime(latest.EvaluationDate)
		if a.After(b) {
			latest = &reports[i]
		}
	}
	return latest, nil
}

func stageFlag(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVarP(p, "stage", "s", "", "Report stage: {"+strings.Join(iq.Stages, "|")+"} (default: build, else the latest)")
	_ = cmd.RegisterFlagCompletionFunc("stage", cobra.FixedCompletions(iq.Stages, cobra.ShellCompDirectiveNoFileComp))
}
