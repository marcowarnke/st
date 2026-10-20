package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"
)

// fakeIQ is a tiny in-memory IQ Server with one evaluated application.
type fakeIQ struct {
	t        *testing.T
	mu       sync.Mutex
	requests []string
	srv      *httptest.Server
}

func newFake(t *testing.T) *fakeIQ {
	keyring.MockInit() // never touch the real OS keyring from tests
	f := &fakeIQ{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	t.Setenv("ST_CONFIG_DIR", t.TempDir())
	t.Setenv("ST_HOST", f.srv.URL)
	t.Setenv("ST_TOKEN", "code:pass")
	t.Setenv("ST_USER", "")
	t.Setenv("ST_APP", "")
	return f
}

func (f *fakeIQ) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func mavenID(g, a, v string) map[string]any {
	return map[string]any{"format": "maven", "coordinates": map[string]any{"groupId": g, "artifactId": a, "version": v, "extension": "jar", "classifier": ""}}
}

func secViolation(policy string, level int, waived bool, reasons ...string) map[string]any {
	var conds []any
	for _, r := range reasons {
		conds = append(conds, map[string]any{"conditionSummary": "Security Vulnerability Severity >= 7", "conditionReason": r})
	}
	return map[string]any{"policyId": "p-" + policy, "policyName": policy, "policyThreatCategory": "SECURITY", "policyThreatLevel": level,
		"waived": waived, "grandfathered": false, "constraints": []any{map[string]any{"constraintId": "c1", "constraintName": "cvss", "conditions": conds}}}
}

const (
	jacksonPurl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.1?type=jar"
	yamlPurl    = "pkg:maven/org.yaml/snakeyaml@1.26?type=jar"
	starterPurl = "pkg:maven/org.springframework.boot/spring-boot-starter@2.7.0?type=jar"
	lodashPurl  = "pkg:npm/lodash@4.17.15"
	waivedPurl  = "pkg:maven/commons-io/commons-io@2.4?type=jar"
	licensePurl = "pkg:maven/org.gpl/thing@1.0?type=jar"
)

func policyReport() map[string]any {
	license := map[string]any{"policyId": "lic", "policyName": "License-Banned", "policyThreatCategory": "LEGAL", "policyThreatLevel": 10, "waived": false}
	return map[string]any{
		"reportTime": 1700000000000, "reportTitle": "Build Report", "initiator": "ci",
		"application": map[string]any{"id": "a1", "publicId": "my-service", "name": "My Service", "organizationId": "o1"},
		"components": []any{
			map[string]any{"hash": "h1", "packageUrl": jacksonPurl, "componentIdentifier": mavenID("com.fasterxml.jackson.core", "jackson-databind", "2.9.10.1"),
				"violations": []any{secViolation("Security-High", 9, false,
					"Found security vulnerability CVE-2020-36518 with severity 7.5.",
					"Found security vulnerability CVE-2022-42003 with severity 7.5."), license}},
			map[string]any{"hash": "h2", "packageUrl": yamlPurl, "componentIdentifier": mavenID("org.yaml", "snakeyaml", "1.26"),
				"violations": []any{secViolation("Security-High", 8, false, "Found security vulnerability CVE-2022-1471 with severity 9.8.")}},
			map[string]any{"hash": "h3", "packageUrl": lodashPurl, "componentIdentifier": map[string]any{"format": "npm", "coordinates": map[string]any{"packageId": "lodash", "version": "4.17.15"}},
				"violations": []any{secViolation("Security-Medium", 7, false, "Found security vulnerability sonatype-2020-0001 with severity 6.5.")}},
			map[string]any{"hash": "h4", "packageUrl": waivedPurl, "componentIdentifier": mavenID("commons-io", "commons-io", "2.4"),
				"violations": []any{secViolation("Security-High", 9, true, "Found security vulnerability CVE-2021-29425 with severity 9.1.")}},
			map[string]any{"hash": "h5", "packageUrl": licensePurl, "violations": []any{license}},
		},
	}
}

func rawReport() map[string]any {
	issue := func(ref string, sev float64) map[string]any {
		return map[string]any{"source": "cve", "reference": ref, "severity": sev, "status": "Open", "url": "https://nvd/" + ref, "threatCategory": "critical"}
	}
	dep := func(direct bool, parents ...string) map[string]any {
		if parents == nil {
			parents = []string{}
		}
		return map[string]any{"directDependency": direct, "innerSource": false, "parentComponentPurls": parents}
	}
	return map[string]any{"components": []any{
		map[string]any{"hash": "h1", "packageUrl": jacksonPurl, "dependencyData": dep(true),
			"securityData": map[string]any{"securityIssues": []any{issue("CVE-2020-36518", 7.5), issue("CVE-2022-42003", 7.5), issue("CVE-2019-0001", 3.1)}}},
		map[string]any{"hash": "h2", "packageUrl": yamlPurl, "dependencyData": dep(false, starterPurl),
			"securityData": map[string]any{"securityIssues": []any{issue("CVE-2022-1471", 9.8)}}},
		map[string]any{"hash": "h3", "packageUrl": lodashPurl, "dependencyData": dep(false),
			"securityData": map[string]any{"securityIssues": []any{issue("sonatype-2020-0001", 6.5)}}},
		map[string]any{"hash": "h4", "packageUrl": waivedPurl, "dependencyData": dep(true)},
	}}
}

func change(typ, purl string, id map[string]any) map[string]any {
	return map[string]any{"type": typ, "data": map[string]any{"component": map[string]any{"packageUrl": purl, "componentIdentifier": id}}}
}

func remediation(artifact string) map[string]any {
	var changes []any
	switch artifact {
	case "jackson-databind":
		yes := true
		a := change("recommended-non-breaking", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.7.1?type=jar", mavenID("com.fasterxml.jackson.core", "jackson-databind", "2.12.7.1"))
		b := change("next-no-violations", "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4.2?type=jar", mavenID("com.fasterxml.jackson.core", "jackson-databind", "2.13.4.2"))
		// IQ may list the current version when it already satisfies a strategy.
		cur := change("next-non-failing", jacksonPurl, mavenID("com.fasterxml.jackson.core", "jackson-databind", "2.9.10.1"))
		a["directDependency"], b["directDependency"] = yes, yes
		changes = []any{cur, b, a}
	case "snakeyaml":
		c := change("next-no-violations-with-dependencies", "pkg:maven/org.yaml/snakeyaml@2.0?type=jar", mavenID("org.yaml", "snakeyaml", "2.0"))
		c["directDependency"] = false
		c["directDependencyData"] = []any{map[string]any{"component": map[string]any{
			"packageUrl": "pkg:maven/org.springframework.boot/spring-boot-starter@3.0.0?type=jar", "hash": nil,
			"componentIdentifier": mavenID("org.springframework.boot", "spring-boot-starter", "3.0.0"),
			"displayName":         "org.springframework.boot : spring-boot-starter : 3.0.0"}}}
		changes = []any{c}
	}
	return map[string]any{"remediation": map[string]any{"versionChanges": changes}}
}

func (f *fakeIQ) handle(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "code" || p != "pass" {
		w.WriteHeader(401)
		fmt.Fprint(w, "Unauthorized")
		return
	}
	key := r.Method + " " + r.URL.Path
	f.mu.Lock()
	f.requests = append(f.requests, key+"?"+r.URL.RawQuery)
	f.mu.Unlock()
	apps := []any{
		map[string]any{"id": "a1", "publicId": "my-service", "name": "My Service", "organizationId": "o1"},
		map[string]any{"id": "a2", "publicId": "other", "name": "Other", "organizationId": "o1"},
	}
	var out any
	switch key {
	case "GET /api/v2/applications":
		switch r.URL.Query().Get("publicId") {
		case "":
			out = map[string]any{"applications": apps}
		case "my-service":
			out = map[string]any{"applications": apps[:1]}
		case "other":
			out = map[string]any{"applications": apps[1:]}
		default:
			out = map[string]any{"applications": []any{}}
		}
	case "GET /api/v2/sourceControl/application/a1":
		out = map[string]any{"repositoryUrl": "https://bitbucket.corp/scm/proj/my-service.git", "baseBranch": "main"}
	case "GET /api/v2/reports/applications/a1":
		out = []any{
			map[string]any{"stage": "release", "applicationId": "a1", "evaluationDate": "2026-01-01T10:00:00.000-05:00",
				"reportHtmlUrl": "ui/links/application/my-service/report/r2", "latestReportHtmlUrl": "ui/links/application/my-service/latestReport/release",
				"reportDataUrl": "api/v2/applications/my-service/reports/r2"},
			map[string]any{"stage": "build", "applicationId": "a1", "evaluationDate": "2026-02-01T10:00:00.000-05:00",
				"reportHtmlUrl": "ui/links/application/my-service/report/r1", "latestReportHtmlUrl": "ui/links/application/my-service/latestReport/build",
				"reportDataUrl": "api/v2/applications/my-service/reports/r1"},
		}
	case "GET /api/v2/reports/applications/a2":
		out = []any{}
	case "GET /api/v2/applications/my-service/reports/r1/policy", "GET /api/v2/applications/my-service/reports/r2/policy":
		out = policyReport()
	case "GET /api/v2/applications/my-service/reports/r1/raw", "GET /api/v2/applications/my-service/reports/r2/raw":
		out = rawReport()
	case "POST /api/v2/components/remediation/application/a1":
		var body struct {
			ComponentIdentifier struct {
				Coordinates map[string]any `json:"coordinates"`
			} `json:"componentIdentifier"`
		}
		data, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(data, &body); err != nil {
			w.WriteHeader(400)
			return
		}
		name, _ := body.ComponentIdentifier.Coordinates["artifactId"].(string)
		if name == "" {
			name, _ = body.ComponentIdentifier.Coordinates["packageId"].(string)
		}
		out = remediation(name)
	case "GET /api/v2/vulnerabilities/CVE-2022-42003":
		out = map[string]any{
			"identifier": "CVE-2022-42003", "vulnerabilityLink": "https://nvd/CVE-2022-42003",
			"source":       map[string]any{"shortName": "CVE", "longName": "National Vulnerability Database"},
			"mainSeverity": map[string]any{"source": "cve_cvss_3", "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
			"weakness":     map[string]any{"cweSource": "CVE", "cweIds": []any{map[string]any{"id": "502", "uri": "https://cwe.mitre.org/data/definitions/502.html"}}},
			"description":  "Deep wrapper array nesting causes resource exhaustion.", "recommendationMarkdown": "Upgrade to 2.13.4.1 or later.",
			"vulnerableVersionRanges": []any{"[2.4.0-rc1,2.12.7.1)", "[2.13.0,2.13.4.1)"}, "kevData": map[string]any{"isKev": true},
		}
	default:
		w.WriteHeader(404)
		fmt.Fprintf(w, "no route for %s", key)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func run(t *testing.T, in string, args ...string) (string, string, int) {
	t.Helper()
	return runWith(t, false, in, args...)
}

// runTTY runs as if attached to a terminal (prompts enabled; no color in tests).
func runTTY(t *testing.T, in string, args ...string) (string, string, int) {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	return runWith(t, true, in, args...)
}

func runWith(t *testing.T, tty bool, in string, args ...string) (string, string, int) {
	t.Helper()
	var o, e bytes.Buffer
	stdout, stderr, stdin = &o, &e, strings.NewReader(in)
	isTTY = func() bool { return tty }
	root := NewRoot()
	root.SetArgs(args)
	root.SetOut(&o)
	root.SetErr(&e)
	code := 0
	if err := root.Execute(); err != nil {
		if ee, ok := err.(*ExitError); ok {
			code = ee.Code
			if ee.Err != nil {
				e.WriteString(ee.Err.Error())
			}
		} else {
			code = 1
			e.WriteString(err.Error())
		}
	}
	return o.String(), e.String(), code
}

func decode[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decoding %q: %v", s, err)
	}
	return v
}

func TestVulnList(t *testing.T) {
	newFake(t)
	out, errOut, code := run(t, "", "vuln", "list", "-A", "my-service")
	if code != 0 {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	want := "9\t" + jacksonPurl + "\tdirect\tCVE-2020-36518,CVE-2022-42003\tSecurity-High\n" +
		"8\t" + yamlPurl + "\ttransitive\tCVE-2022-1471\tSecurity-High\n" +
		"7\t" + lodashPurl + "\ttransitive\tsonatype-2020-0001\tSecurity-Medium\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}

	out, _, _ = run(t, "", "vuln", "list", "-A", "my-service", "--transitive", "--json", "name,parents,cves,stage,reportUrl")
	rows := decode[[]map[string]any](t, out)
	if len(rows) != 2 || rows[0]["name"] != "org.yaml:snakeyaml" || rows[0]["stage"] != "build" {
		t.Fatalf("rows=%v", rows)
	}
	if p := rows[0]["parents"].([]any); len(p) != 1 || p[0] != starterPurl {
		t.Fatalf("parents=%v", p)
	}
	if c := rows[0]["cves"].([]any)[0].(map[string]any); c["id"] != "CVE-2022-1471" || c["url"] != "https://nvd/CVE-2022-1471" {
		t.Fatalf("cve=%v", c)
	}
	if !strings.HasSuffix(rows[0]["reportUrl"].(string), "/ui/links/application/my-service/report/r1") {
		t.Fatalf("reportUrl=%v", rows[0]["reportUrl"])
	}

	out, _, _ = run(t, "", "vuln", "list", "-A", "my-service", "--cve", "cve-2022-42003", "--json", "name", "--jq", ".[].name")
	if out != "com.fasterxml.jackson.core:jackson-databind\n" {
		t.Fatalf("--cve: %q", out)
	}
	out, _, _ = run(t, "", "vuln", "list", "-A", "my-service", "--min-threat", "8", "--direct", "--json", "name", "--jq", "length")
	if out != "1\n" {
		t.Fatalf("--min-threat --direct: %q", out)
	}
	out, _, _ = run(t, "", "vuln", "list", "-A", "my-service", "--include-waived", "--json", "name,waived", "--jq", `.[] | select(.waived) | .name`)
	if out != "commons-io:commons-io\n" {
		t.Fatalf("--include-waived: %q", out)
	}
	out, _, _ = run(t, "", "vuln", "list", "-A", "my-service", "--stage", "release", "--json", "stage", "--jq", ".[0].stage")
	if out != "release\n" {
		t.Fatalf("--stage: %q", out)
	}
	_, errOut, code = run(t, "", "vuln", "list", "-A", "my-service", "--stage", "operate")
	if code != 1 || !strings.Contains(errOut, "no operate report; available stages: build, release") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	_, errOut, code = run(t, "", "vuln", "list", "-A", "other")
	if code != 1 || !strings.Contains(errOut, "not been evaluated") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	_, errOut, code = run(t, "", "vuln", "list", "-A", "my-service", "--json", "nope")
	if code == 0 || !strings.Contains(errOut, "Unknown JSON field") {
		t.Fatalf("err=%q", errOut)
	}
}

func TestVulnListTTY(t *testing.T) {
	newFake(t)
	out, errOut, code := runTTY(t, "", "vuln", "list", "-A", "my-service")
	if code != 0 {
		t.Fatal(errOut)
	}
	for _, want := range []string{"Showing 3 vulnerable components in my-service (build", "THREAT", "com.fasterxml.jackson.core:jackson-databind", "CVE-2020-36518 CVE-2022-42003", "/report/r1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestFix(t *testing.T) {
	f := newFake(t)
	out, errOut, code := run(t, "", "fix", "-A", "my-service", "--json", "name,current,target,strategy,complete,breaking,dependency,parents,available,resolves,manifestHint")
	if code != exitNoRemediation || !strings.Contains(errOut, "1 of 3 components have no remediation") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	rows := decode[[]map[string]any](t, out)
	if len(rows) != 3 {
		t.Fatalf("rows=%v", rows)
	}
	j, y, l := rows[0], rows[1], rows[2]
	// Golden version wins over next-no-violations; the current version is ignored.
	if j["target"] != "2.12.7.1" || j["strategy"] != "recommended-non-breaking" || j["breaking"] != false || j["complete"] != true || j["dependency"] != "direct" {
		t.Fatalf("jackson=%v", j)
	}
	if len(j["resolves"].([]any)) != 2 {
		t.Fatalf("resolves=%v", j["resolves"])
	}
	// Transitive: bump the parent; its major changes.
	p := y["parents"].([]any)[0].(map[string]any)
	if y["dependency"] != "transitive" || p["name"] != "org.springframework.boot:spring-boot-starter" || p["current"] != "2.7.0" || p["target"] != "3.0.0" || y["breaking"] != true {
		t.Fatalf("snakeyaml=%v", y)
	}
	if !strings.Contains(y["manifestHint"].(string), "bump the parent") {
		t.Fatalf("hint=%v", y["manifestHint"])
	}
	if l["available"] != false || l["target"] != "" || len(l["resolves"].([]any)) != 0 || !strings.Contains(l["manifestHint"].(string), "npm why lodash") {
		t.Fatalf("lodash=%v", l)
	}
	if n := f.count("POST /api/v2/components/remediation/application/a1?includeParentRemediation=true&stageId=build"); n != 3 {
		t.Fatalf("remediation requests=%d: %v", n, f.requests)
	}

	// Narrowing by name, purl without version, or CVE; exit 0 when all are fixable.
	for _, arg := range []string{"com.fasterxml.jackson.core:jackson-databind", "pkg:maven/com.fasterxml.jackson.core/jackson-databind", jacksonPurl, "CVE-2022-42003"} {
		out, errOut, code = run(t, "", "fix", arg, "-A", "my-service", "--json", "target", "--jq", ".[].target")
		if code != 0 || out != "2.12.7.1\n" {
			t.Fatalf("%s: code=%d out=%q err=%q", arg, code, out, errOut)
		}
	}
	out, _, code = run(t, "", "fix", "com.fasterxml.jackson.core:jackson-databind", "-A", "my-service", "--strategy", "next-no-violations", "--json", "target,complete,breaking", "--jq", ".[] | [.target, .complete, .breaking] | @tsv")
	if code != 0 || out != "2.13.4.2\ttrue\tfalse\n" {
		t.Fatalf("--strategy: code=%d out=%q", code, out)
	}
	_, errOut, code = run(t, "", "fix", "pkg:npm/left-pad", "-A", "my-service")
	if code != 1 || !strings.Contains(errOut, "has no security violations") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	_, errOut, code = run(t, "", "fix", "-A", "my-service", "--strategy", "best")
	if code != 1 || !strings.Contains(errOut, "invalid --strategy") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}

	out, _, code = run(t, "", "fix", "-A", "my-service")
	if code != exitNoRemediation || !strings.HasPrefix(out, jacksonPurl+"\t2.9.10.1\t2.12.7.1\tdirect\trecommended-non-breaking\t") ||
		!strings.Contains(out, "via org.springframework.boot:spring-boot-starter 2.7.0 → 3.0.0") || !strings.Contains(out, lodashPurl+"\t4.17.15\t\tno remediation") {
		t.Fatalf("plain: code=%d out=%q", code, out)
	}
	out, _, _ = runTTY(t, "", "fix", "-A", "my-service")
	if !strings.Contains(out, "⚠ major bump") || !strings.Contains(out, "2.9.10.1 → 2.12.7.1") {
		t.Fatalf("tty: %s", out)
	}
}

func TestVulnView(t *testing.T) {
	newFake(t)
	out, errOut, code := run(t, "", "vuln", "view", "CVE-2022-42003")
	if code != 0 {
		t.Fatal(errOut)
	}
	for _, want := range []string{"CVE-2022-42003", "Severity:   7.5 CVSS:3.1", "Weakness:   CWE-502", "Exploited:  yes", "Vulnerable: [2.4.0-rc1,2.12.7.1) [2.13.0,2.13.4.1)", "Recommendation\nUpgrade to 2.13.4.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	out, _, _ = run(t, "", "vuln", "view", "CVE-2022-42003", "--json", "score,cwes,kev", "--jq", "[.score, .cwes[0], .kev] | @tsv")
	if out != "7.5\tCWE-502\ttrue\n" {
		t.Fatalf("json: %q", out)
	}
	if _, errOut, code = run(t, "", "vuln", "view", "CVE-0000-0000"); code != 1 || !strings.Contains(errOut, "HTTP 404") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestAppListViewAndAPI(t *testing.T) {
	newFake(t)
	out, _, _ := run(t, "", "app", "list")
	if out != "my-service\tMy Service\ta1\nother\tOther\ta2\n" {
		t.Fatalf("list=%q", out)
	}
	out, _, _ = run(t, "", "app", "list", "-S", "OTH", "--json", "publicId", "--jq", ".[].publicId")
	if out != "other\n" {
		t.Fatalf("search=%q", out)
	}
	out, _, _ = run(t, "", "app", "view", "my-service", "--json", "repositoryUrl,reports", "--jq", `[.repositoryUrl, (.reports | map(.stage) | join(","))] | @tsv`)
	if out != "https://bitbucket.corp/scm/proj/my-service.git\tbuild,release\n" {
		t.Fatalf("view=%q", out)
	}
	out, _, _ = runTTY(t, "", "app", "view", "my-service")
	if !strings.Contains(out, "My Service (my-service)") || !strings.Contains(out, "Repository: https://bitbucket.corp/scm/proj/my-service.git (main)") {
		t.Fatalf("view tty=%s", out)
	}
	out, errOut, code := run(t, "", "api", "reports/applications/{appId}", "-A", "my-service", "--jq", ".[].stage")
	if code != 0 || out != "release\nbuild\n" {
		t.Fatalf("api: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestStatus(t *testing.T) {
	newFake(t)
	out, errOut, code := run(t, "", "status", "--json", "application,components,direct,threatLevel,error")
	if code != 0 {
		t.Fatal(errOut)
	}
	rows := decode[[]map[string]any](t, out)
	if len(rows) != 2 || rows[0]["application"] != "my-service" || rows[0]["components"] != 3.0 || rows[0]["direct"] != 1.0 || rows[0]["threatLevel"] != 9.0 {
		t.Fatalf("rows=%v", rows)
	}
	if !strings.Contains(rows[1]["error"].(string), "not been evaluated") {
		t.Fatalf("other=%v", rows[1])
	}
}

func TestAuthFailureExitCode(t *testing.T) {
	newFake(t)
	t.Setenv("ST_TOKEN", "code:wrong")
	_, errOut, code := runCLI(t, "vuln", "list", "-A", "my-service")
	if code != exitAuth || !strings.Contains(errOut, "HTTP 401") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	t.Setenv("ST_TOKEN", "")
	t.Setenv("ST_HOST", "")
	if _, _, code = runCLI(t, "vuln", "list"); code != exitAuth {
		t.Fatalf("no host: code=%d", code)
	}
}

// runCLI goes through Execute, which maps errors to exit codes.
func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var o, e bytes.Buffer
	stdout, stderr, stdin = &o, &e, strings.NewReader("")
	isTTY = func() bool { return false }
	old := osArgs
	osArgs = args
	defer func() { osArgs = old }()
	code := Execute()
	return o.String(), e.String(), code
}
