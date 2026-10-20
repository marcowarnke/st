package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestWaive(t *testing.T) {
	f := newFake(t)
	now = func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })

	_, errOut, code := run(t, "", "waive", "-A", "my-service", "lodash")
	if code != 1 || !strings.Contains(errOut, "--comment is required") {
		t.Fatalf("no comment: code=%d err=%q", code, errOut)
	}
	for _, bad := range []string{"0d", "91d", "never", "2026-10-01", "2027-06-01"} {
		if _, errOut, code := run(t, "", "waive", "-A", "my-service", "lodash", "-m", "x", "--expires", bad); code != 1 || !strings.Contains(errOut, "--expires") {
			t.Fatalf("--expires %s: code=%d err=%q", bad, code, errOut)
		}
	}
	if n := f.count("POST"); n != 0 {
		t.Fatalf("%d POSTs before any valid waive", n)
	}

	out, errOut, code := run(t, "", "waive", "-A", "my-service", "lodash", "-m", "not reachable", "--dry-run", "--json", "violationId,expiresAt,scope,dryRun")
	if code != 0 {
		t.Fatal(errOut)
	}
	rows := decode[[]map[string]any](t, out)
	if len(rows) != 1 || rows[0]["violationId"] != "pv-Security-Medium-7" || rows[0]["expiresAt"] != "2026-10-27T12:00:00.000+0000" || rows[0]["scope"] != "EXACT_COMPONENT" || rows[0]["dryRun"] != true {
		t.Fatalf("dry run: %v", rows)
	}
	if n := f.count("POST"); n != 0 {
		t.Fatalf("dry run sent %d POSTs", n)
	}

	_, errOut, code = run(t, "", "waive", "-A", "my-service", "pkg:maven/org.yaml/snakeyaml", "-m", "  SafeConstructor only ", "--expires", "2w", "--all-versions")
	if code != 0 || !strings.Contains(errOut, "Waived Security-High violation (threat 8) of org.yaml:snakeyaml (all versions) in my-service until 2026-11-03") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	body := decode[map[string]any](t, f.bodies["POST /api/v2/policyWaivers/application/a1/pv-Security-High-8"])
	if body["comment"] != "SafeConstructor only" || body["expiryTime"] != "2026-11-03T12:00:00.000+0000" || body["matcherStrategy"] != "ALL_VERSIONS" {
		t.Fatalf("body=%v", body)
	}

	_, errOut, code = run(t, "", "waive", "-A", "my-service", "lodash", "-m", "x", "--policy", "Security-High")
	if code != 1 || !strings.Contains(errOut, "no unwaived Security-High violation") {
		t.Fatalf("--policy: code=%d err=%q", code, errOut)
	}
	_, errOut, code = run(t, "", "waive", "-A", "my-service", "commons-io:commons-io", "-m", "x")
	if code != 1 || !strings.Contains(errOut, "no unwaived security violations") {
		t.Fatalf("already waived: code=%d err=%q", code, errOut)
	}
}

func TestVulnListViolations(t *testing.T) {
	newFake(t)
	out, _, _ := run(t, "", "vuln", "list", "-A", "my-service", "--json", "name,violations", "--jq", ".[0].violations[0].id")
	if out != "pv-Security-High-9\n" {
		t.Fatalf("got %q", out)
	}
}
