package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/itchyny/gojq"
	"github.com/spf13/cobra"
)

func colorOn() bool { return isTTY() && os.Getenv("NO_COLOR") == "" }

func paint(code, s string) string {
	if !colorOn() {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func green(s string) string   { return paint("32", s) }
func red(s string) string     { return paint("31", s) }
func yellow(s string) string  { return paint("33", s) }
func magenta(s string) string { return paint("35", s) }
func gray(s string) string    { return paint("90", s) }
func bold(s string) string    { return paint("1", s) }
func cyan(s string) string    { return paint("36", s) }

// parseTime parses IQ Server timestamps ("2015-01-16T13:14:32.139-05:00").
func parseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ago renders an IQ timestamp relative to now, or as-is if unparseable.
func ago(s string) string {
	t, ok := parseTime(s)
	if !ok {
		return s
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "less than a minute ago"
	case d < time.Hour:
		return plural(int(d.Minutes()), "minute") + " ago"
	case d < 24*time.Hour:
		return plural(int(d.Hours()), "hour") + " ago"
	case d < 30*24*time.Hour:
		return plural(int(d.Hours()/24), "day") + " ago"
	case d < 365*24*time.Hour:
		return plural(int(d.Hours()/24/30), "month") + " ago"
	}
	return plural(int(d.Hours()/24/365), "year") + " ago"
}

func plural(n int, unit string) string {
	if n == 1 {
		return "about 1 " + unit
	}
	return fmt.Sprintf("about %d %ss", n, unit)
}

func openBrowser(u string) error {
	if isTTY() {
		fmt.Fprintf(stderr, "Opening %s in your browser.\n", u)
	}
	if b := os.Getenv("BROWSER"); b != "" {
		return exec.Command(b, u).Start()
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
	return exec.Command("xdg-open", u).Start()
}

// exporter implements gh's --json / --jq / --template trio.
type exporter struct {
	fields   []string
	jq       string
	template string
}

func addJSONFlags(cmd *cobra.Command, e *exporter, available []string) {
	sort.Strings(available)
	f := cmd.Flags()
	f.StringSliceVar(&e.fields, "json", nil, "Output JSON with the specified `fields`")
	f.StringVarP(&e.jq, "jq", "q", "", "Filter JSON output using a jq `expression`")
	f.StringVarP(&e.template, "template", "t", "", "Format JSON output using a Go template")
	_ = f.SetAnnotation("json", "fields", available)
	prev := cmd.PreRunE
	cmd.PreRunE = func(c *cobra.Command, args []string) error {
		if (e.jq != "" || e.template != "") && len(e.fields) == 0 {
			return usageErr("cannot use `--jq` or `--template` without specifying `--json`")
		}
		for _, fld := range e.fields {
			if !contains(available, fld) {
				return fmt.Errorf("Unknown JSON field: %q\nAvailable fields:\n  %s", fld, strings.Join(available, "\n  "))
			}
		}
		if prev != nil {
			return prev(c, args)
		}
		return nil
	}
}

func (e *exporter) enabled() bool { return len(e.fields) > 0 }

func (e *exporter) wants(f string) bool { return contains(e.fields, f) }

func (e *exporter) write(w io.Writer, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	switch {
	case e.jq != "":
		return runJQ(w, e.jq, raw)
	case e.template != "":
		var v any
		_ = json.Unmarshal(raw, &v)
		t, err := template.New("").Funcs(template.FuncMap{
			"json": func(v any) string { b, _ := json.Marshal(v); return string(b) },
			"join": func(sep string, v []any) string {
				var s []string
				for _, x := range v {
					s = append(s, fmt.Sprint(x))
				}
				return strings.Join(s, sep)
			},
		}).Parse(e.template)
		if err != nil {
			return err
		}
		return t.Execute(w, v)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return err
	}
	buf.WriteByte('\n')
	_, err = w.Write(buf.Bytes())
	return err
}

func runJQ(w io.Writer, expr string, raw []byte) error {
	q, err := gojq.Parse(expr)
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	iter := q.Run(v)
	for {
		out, ok := iter.Next()
		if !ok {
			return nil
		}
		if err, ok := out.(error); ok {
			return err
		}
		if s, ok := out.(string); ok {
			fmt.Fprintln(w, s)
			continue
		}
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// pick filters a map to the requested fields.
func pick(m map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		out[f] = m[f]
	}
	return out
}
