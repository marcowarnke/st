package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func newAPICmd() *cobra.Command {
	var method, hostname, input, jq, appFlag string
	var rawFields, typedFields, headers []string
	var include, silent bool
	cmd := &cobra.Command{
		Use:   "api <endpoint> [flags]",
		Short: "Make an authenticated IQ Server API request",
		Long: `Make an authenticated HTTP request to the IQ Server REST API and print the response.

The endpoint is a path such as "api/v2/applications". Paths not starting
with "api/" or "rest/" are prefixed with "api/v2/".

The placeholders {app} (public ID) and {appId} (internal ID) are replaced
with the application of the current checkout (or -A).

The default method is GET without parameters and POST with them. Pass
-X GET to send -f/-F fields as query parameters.

-f key=value adds a string parameter; -F key=value adds a typed one
(true, false, null, integers, and @file to read a value from a file;
"@-" reads from stdin). Nested keys use key[sub]=value.`,
		Example: `  $ st api applications --jq '.applications[].publicId'
  $ st api reports/applications/{appId}
  $ st api -X POST components/remediation/application/{appId} --input component.json
  $ st api policies`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint := strings.TrimLeft(args[0], "/")
			if !strings.HasPrefix(endpoint, "api/") && !strings.HasPrefix(endpoint, "rest/") {
				endpoint = "api/v2/" + endpoint
			}
			c, err := clientFor(hostname)
			if err != nil {
				return err
			}
			if strings.Contains(endpoint, "{app") {
				app, err := resolveApp(c, appFlag)
				if err != nil {
					return err
				}
				endpoint = strings.NewReplacer("{appId}", url.PathEscape(app.ID), "{app}", url.PathEscape(app.PublicID)).Replace(endpoint)
			}
			params, err := parseFields(rawFields, typedFields)
			if err != nil {
				return err
			}
			if method == "" {
				method = "GET"
				if len(params) > 0 || input != "" {
					method = "POST"
				}
			}
			method = strings.ToUpper(method)
			query := url.Values{}
			var body io.Reader
			switch {
			case input != "":
				if input == "-" {
					body = stdin
				} else {
					f, err := os.Open(input)
					if err != nil {
						return err
					}
					defer f.Close()
					body = f
				}
				for k, v := range params {
					query.Set(k, fmt.Sprint(v))
				}
			case method == "GET":
				for k, v := range params {
					query.Set(k, fmt.Sprint(v))
				}
			case len(params) > 0:
				data, err := json.Marshal(params)
				if err != nil {
					return err
				}
				body = bytes.NewReader(data)
			}
			if i := strings.Index(endpoint, "?"); i >= 0 {
				extra, err := url.ParseQuery(endpoint[i+1:])
				if err != nil {
					return err
				}
				for k, v := range extra {
					query[k] = v
				}
				endpoint = endpoint[:i]
			}
			h := http.Header{}
			for _, hv := range headers {
				k, v, ok := strings.Cut(hv, ":")
				if !ok {
					return usageErr("header %q: expected \"key: value\"", hv)
				}
				h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
			}
			resp, err := c.Raw(method, endpoint, query, h, body)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if include {
				fmt.Fprintf(stdout, "%s %s\n", resp.Proto, resp.Status)
				for k, vs := range resp.Header {
					for _, v := range vs {
						fmt.Fprintf(stdout, "%s: %s\n", k, v)
					}
				}
				fmt.Fprintln(stdout)
			}
			raw, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			return emit(raw, jq, silent)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&method, "method", "X", "", "The HTTP method for the request")
	f.StringArrayVarP(&rawFields, "raw-field", "f", nil, "Add a string parameter in `key=value` format")
	f.StringArrayVarP(&typedFields, "field", "F", nil, "Add a typed parameter in `key=value` format")
	f.StringArrayVarP(&headers, "header", "H", nil, "Add a HTTP request header in `key:value` format")
	f.StringVar(&input, "input", "", "The `file` to use as body for the HTTP request (use \"-\" to read from standard input)")
	f.BoolVarP(&include, "include", "i", false, "Include HTTP response status line and headers in the output")
	f.BoolVar(&silent, "silent", false, "Do not print the response body")
	f.StringVarP(&jq, "jq", "q", "", "Query to select values from the response using jq syntax")
	f.StringVar(&hostname, "hostname", "", "The IQ Server host for the request")
	addAppFlag(cmd, &appFlag)
	return cmd
}

func emit(raw []byte, jq string, silent bool) error {
	if silent || len(raw) == 0 {
		return nil
	}
	if jq != "" {
		return runJQ(stdout, jq, raw)
	}
	var buf bytes.Buffer
	if json.Indent(&buf, raw, "", "  ") == nil && isTTY() {
		buf.WriteByte('\n')
		_, err := stdout.Write(buf.Bytes())
		return err
	}
	_, err := stdout.Write(raw)
	if err == nil && !bytes.HasSuffix(raw, []byte("\n")) {
		fmt.Fprintln(stdout)
	}
	return err
}

// parseFields builds a (possibly nested) parameter map from -f and -F values.
func parseFields(raw, typed []string) (map[string]any, error) {
	out := map[string]any{}
	add := func(kv string, isTyped bool) error {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("field %q: expected key=value", kv)
		}
		var val any = v
		if isTyped {
			var err error
			if val, err = typedValue(v); err != nil {
				return err
			}
		}
		keys := strings.Split(strings.ReplaceAll(k, "]", ""), "[")
		m := out
		for _, key := range keys[:len(keys)-1] {
			next, ok := m[key].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[key] = next
			}
			m = next
		}
		m[keys[len(keys)-1]] = val
		return nil
	}
	for _, kv := range raw {
		if err := add(kv, false); err != nil {
			return nil, err
		}
	}
	for _, kv := range typed {
		if err := add(kv, true); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func typedValue(v string) (any, error) {
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "null":
		return nil, nil
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n, nil
	}
	if strings.HasPrefix(v, "@") {
		var data []byte
		var err error
		if v == "@-" {
			data, err = io.ReadAll(stdin)
		} else {
			data, err = os.ReadFile(v[1:])
		}
		return strings.TrimRight(string(data), "\n"), err
	}
	return v, nil
}
