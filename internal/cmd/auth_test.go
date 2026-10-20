package cmd

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/marcowarnke/st/internal/config"
)

func configFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(config.Path())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAuthLoginKeyring(t *testing.T) {
	f := newFake(t)
	t.Setenv("ST_TOKEN", "")
	t.Setenv("ST_HOST", "")

	_, errOut, code := run(t, "code:pass\n", "auth", "login", "--hostname", f.srv.URL, "--with-token")
	if code != 0 || !strings.Contains(errOut, "Logged in to 127.0.0.1 as code (token stored in keyring)") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	if strings.Contains(configFile(t), "pass") {
		t.Fatal("passcode leaked into config file")
	}
	if tok, _ := keyring.Get("st:127.0.0.1", "code"); tok != "pass" {
		t.Fatalf("keyring token=%q", tok)
	}
	out, errOut, code := run(t, "", "app", "list", "--json", "publicId", "--jq", ".[0].publicId")
	if code != 0 || out != "my-service\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	out, _, _ = run(t, "", "auth", "status")
	if !strings.Contains(out, "as code (keyring)") || strings.Contains(out, "pass") {
		t.Fatalf("status=%q", out)
	}
	out, _, _ = run(t, "", "auth", "token")
	if out != "code:pass\n" {
		t.Fatalf("token=%q", out)
	}
	if _, errOut, code = run(t, "", "auth", "logout"); code != 0 {
		t.Fatal(errOut)
	}
	if _, err := keyring.Get("st:127.0.0.1", "code"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("token still in keyring after logout: %v", err)
	}
}

func TestAuthLoginRejectsBadToken(t *testing.T) {
	f := newFake(t)
	t.Setenv("ST_TOKEN", "")
	_, errOut, code := run(t, "code:nope", "auth", "login", "-h", f.srv.URL, "--with-token")
	if code != 1 || !strings.Contains(errOut, "HTTP 401") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	_, errOut, code = run(t, "justapasscode", "auth", "login", "-h", f.srv.URL, "--with-token")
	if code != 1 || !strings.Contains(errOut, `expected "code:passcode"`) {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestAuthLoginKeyringUnavailable(t *testing.T) {
	f := newFake(t)
	keyring.MockInitWithError(errors.New("no secret service"))
	t.Setenv("ST_TOKEN", "")

	_, errOut, code := run(t, "code:pass", "auth", "login", "--hostname", f.srv.URL, "--with-token")
	if code != 0 || !strings.Contains(errOut, "storing it in plain text") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	if !strings.Contains(configFile(t), `"token": "pass"`) {
		t.Fatalf("expected fallback to file, config=%s", configFile(t))
	}
	if out, errOut, code := run(t, "", "app", "list"); code != 0 || !strings.HasPrefix(out, "my-service") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestTokenEnvWithUser(t *testing.T) {
	newFake(t)
	t.Setenv("ST_TOKEN", "pass")
	t.Setenv("ST_USER", "code")
	if out, errOut, code := run(t, "", "app", "list"); code != 0 || !strings.HasPrefix(out, "my-service") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	t.Setenv("ST_USER", "")
	if _, errOut, code := run(t, "", "app", "list"); code != exitAuth || !strings.Contains(errOut, "ST_TOKEN must be") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}
