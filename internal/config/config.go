// Package config stores per-host credentials, modelled after gh's hosts.yml.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zalando/go-keyring"
)

// Host is an IQ Server login. IQ uses HTTP Basic auth: User is the user token
// code (or username), Token the passcode (or password).
type Host struct {
	BaseURL string `json:"base_url"`
	User    string `json:"user,omitempty"`
	Token   string `json:"token,omitempty"`
	// TokenSource is where Resolve found the token: "ST_TOKEN", "keyring" or the config path.
	TokenSource string `json:"-"`
}

type Config struct {
	Hosts map[string]*Host `json:"hosts"`
	path  string
}

func Dir() string {
	if d := os.Getenv("ST_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "st")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "st")
}

func Path() string { return filepath.Join(Dir(), "config.json") }

func Load() (*Config, error) {
	c := &Config{Hosts: map[string]*Host{}, path: Path()}
	data, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", c.path, err)
	}
	if c.Hosts == nil {
		c.Hosts = map[string]*Host{}
	}
	return c, nil
}

func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, append(data, '\n'), 0o600)
}

func (c *Config) HostNames() []string {
	var names []string
	for n := range c.Hosts {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// NormalizeHost turns "iq.corp", "https://iq.corp:8070/ctx/" etc. into a host
// key ("iq.corp") and base URL ("https://iq.corp:8070/ctx").
func NormalizeHost(in string) (key, baseURL string, err error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", "", errors.New("empty hostname")
	}
	if !strings.Contains(in, "://") {
		in = "https://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid hostname %q", in)
	}
	return u.Hostname(), strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

// Resolve picks the host to use. Precedence: explicit name, ST_HOST, the only
// configured host. ST_TOKEN ("code:passcode", or a passcode with ST_USER)
// overrides the stored credentials.
func (c *Config) Resolve(name string) (string, *Host, error) {
	if name == "" {
		name = os.Getenv("ST_HOST")
	}
	var key string
	var h *Host
	if name != "" {
		k, base, err := NormalizeHost(name)
		if err != nil {
			return "", nil, err
		}
		key = k
		if stored, ok := c.Hosts[k]; ok {
			cp := *stored
			h = &cp
		} else {
			h = &Host{BaseURL: base}
		}
	} else {
		switch len(c.Hosts) {
		case 0:
			return "", nil, ErrNoHost
		case 1:
			for k, v := range c.Hosts {
				cp := *v
				key, h = k, &cp
			}
		default:
			return "", nil, fmt.Errorf("multiple hosts configured (%s); set ST_HOST or pass --hostname", strings.Join(c.HostNames(), ", "))
		}
	}
	switch t := os.Getenv("ST_TOKEN"); {
	case t != "":
		if u, p, ok := strings.Cut(t, ":"); ok {
			h.User, h.Token = u, p
		} else {
			if u := os.Getenv("ST_USER"); u != "" {
				h.User = u
			}
			h.Token = t
		}
		h.TokenSource = "ST_TOKEN"
		if h.User == "" {
			return key, h, errors.New("ST_TOKEN must be \"code:passcode\" (or set ST_USER to the token code)")
		}
	case h.Token != "":
		h.TokenSource = c.path
	case h.User != "":
		tok, err := KeyringGet(key, h.User)
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return key, h, fmt.Errorf("reading token for %s from the OS keyring: %w", key, err)
		}
		h.Token, h.TokenSource = tok, "keyring"
	}
	if h.Token == "" {
		return key, h, fmt.Errorf("not logged in to %s: run `st auth login --hostname %s` or set ST_TOKEN", key, key)
	}
	return key, h, nil
}

var ErrNoHost = errors.New("no IQ Server host configured: run `st auth login --hostname <host>` or set ST_HOST and ST_TOKEN")
