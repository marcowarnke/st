package iq

import "testing"

func TestReportID(t *testing.T) {
	for _, tc := range []struct{ data, html, want string }{
		{"api/v2/applications/my-app/reports/abc123/raw", "", "abc123"},
		{"api/v2/applications/my-app/reports/abc123", "", "abc123"},
		{"api/v2/applications/my-app/reports/abc123/", "", "abc123"},
		{"https://iq.corp/api/v2/applications/my-app/reports/abc123/raw?x=1", "", "abc123"},
		{"", "ui/links/application/my-app/report/def456", "def456"},
		{"", "", ""},
	} {
		if got := (ReportInfo{ReportDataURL: tc.data, ReportHTMLURL: tc.html}).ReportID(); got != tc.want {
			t.Errorf("ReportID(%q, %q) = %q, want %q", tc.data, tc.html, got, tc.want)
		}
	}
}
