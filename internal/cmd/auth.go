package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marcowarnke/st/internal/config"
	"github.com/marcowarnke/st/internal/iq"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth <command>",
		Short: "Authenticate st with an IQ Server",
		Long: `Authenticate with a Sonatype IQ Server using a user token
(IQ Server → your user menu → User Token → Access user token). A token is a
code/passcode pair used as HTTP Basic credentials; a username and password
work the same way.

Alternatively set ST_HOST and ST_TOKEN ("code:passcode"); they take
precedence over stored credentials.`,
	}
	for _, sub := range []*cobra.Command{newAuthLoginCmd(), newAuthStatusCmd(), newAuthLogoutCmd(), newAuthTokenCmd()} {
		// -h is --hostname here (as in gh); declaring --help ourselves stops
		// cobra from adding its -h shorthand, which would panic.
		sub.Flags().Bool("help", false, "Show help for command")
		cmd.AddCommand(sub)
	}
	return cmd
}

// verifyLogin makes a cheap authenticated request; IQ answers 401 for bad
// credentials and an empty list for an unknown public ID.
func verifyLogin(c *iq.Client) error {
	return c.Do("GET", "api/v2/applications", url.Values{"publicId": {"st-auth-check"}}, nil, nil)
}

func newAuthLoginCmd() *cobra.Command {
	var hostname string
	var withToken, insecureStorage bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to an IQ Server",
		Long: `Log in to a Sonatype IQ Server with a user token.

The passcode is stored in the OS credential store (macOS Keychain, Windows
Credential Manager, Linux Secret Service). If none is available, or with
--insecure-storage, it is stored in plain text in the config file.

With --with-token, standard input is read as "code:passcode".`,
		Example: `  $ st auth login --hostname iq.example.com
  $ echo "$CODE:$PASSCODE" | st auth login --hostname https://iq.example.com:8070 --with-token`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if hostname == "" {
				hostname = os.Getenv("ST_HOST")
			}
			if hostname == "" {
				if !isTTY() {
					return usageErr("--hostname required when not running interactively")
				}
				hostname = prompt("IQ Server URL (e.g. https://iq.example.com): ")
			}
			key, base, err := config.NormalizeHost(hostname)
			if err != nil {
				return err
			}
			var user, pass string
			switch {
			case withToken:
				data, err := io.ReadAll(stdin)
				if err != nil {
					return err
				}
				var ok bool
				if user, pass, ok = strings.Cut(strings.TrimSpace(string(data)), ":"); !ok {
					return errors.New(`expected "code:passcode" on standard input`)
				}
			case isTTY():
				fmt.Fprintf(stderr, "Create a user token at %s (user menu → User Token → Generate)\n", base)
				user = prompt("Token code (or username): ")
				fmt.Fprint(stderr, "Token passcode (or password): ")
				b, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(stderr)
				if err != nil {
					return err
				}
				pass = string(b)
			default:
				return usageErr("--with-token required when not running interactively")
			}
			user, pass = strings.TrimSpace(user), strings.TrimSpace(pass)
			if user == "" || pass == "" {
				return errors.New("no token provided")
			}
			if err := verifyLogin(newIQ(base, user, pass)); err != nil {
				return fmt.Errorf("validating token against %s: %w", base, err)
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if old, ok := cfg.Hosts[key]; ok && old.User != "" {
				_ = config.KeyringDelete(key, old.User)
			}
			h := &config.Host{BaseURL: base, User: user}
			storage := "keyring"
			if !insecureStorage {
				if err := config.KeyringSet(key, user, pass); err != nil {
					fmt.Fprintf(stderr, "warning: could not store token in the OS keyring (%v); storing it in plain text in %s\n", err, config.Path())
					insecureStorage = true
				}
			}
			if insecureStorage {
				h.Token, storage = pass, config.Path()
			}
			cfg.Hosts[key] = h
			if err := cfg.Save(); err != nil {
				return err
			}
			success("Logged in to %s as %s (token stored in %s)", key, bold(user), storage)
			return nil
		},
	}
	cmd.Flags().StringVarP(&hostname, "hostname", "h", "", "IQ Server host or base URL (include port and context path if any)")
	cmd.Flags().BoolVar(&withToken, "with-token", false, `Read "code:passcode" from standard input`)
	cmd.Flags().BoolVar(&insecureStorage, "insecure-storage", false, "Save the token in plain text instead of the OS credential store")
	return cmd
}

func newAuthStatusCmd() *cobra.Command {
	var hostname string
	var showToken bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display authentication state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			names := cfg.HostNames()
			if hostname != "" {
				names = []string{hostname}
			} else if h := os.Getenv("ST_HOST"); h != "" {
				k, _, _ := config.NormalizeHost(h)
				if !contains(names, k) {
					names = append(names, h)
				}
			}
			if len(names) == 0 {
				return &ExitError{Code: exitAuth, Err: config.ErrNoHost}
			}
			failed := false
			for _, n := range names {
				key, h, err := cfg.Resolve(n)
				fmt.Fprintln(stdout, bold(key))
				if err != nil {
					fmt.Fprintf(stdout, "  %s %v\n", red("X"), err)
					failed = true
					continue
				}
				if err := verifyLogin(newIQ(h.BaseURL, h.User, h.Token)); err != nil {
					fmt.Fprintf(stdout, "  %s Failed to log in to %s using token (%s): %v\n", red("X"), key, h.TokenSource, err)
					failed = true
					continue
				}
				fmt.Fprintf(stdout, "  %s Logged in to %s as %s (%s)\n", green("✓"), key, bold(h.User), h.TokenSource)
				fmt.Fprintf(stdout, "  - API base URL: %s\n", h.BaseURL)
				tok := h.Token
				if !showToken {
					prefix := ""
					if len(tok) > 8 {
						prefix = tok[:4]
					}
					tok = prefix + strings.Repeat("*", 12)
				}
				fmt.Fprintf(stdout, "  - Token: %s\n", tok)
			}
			if failed {
				return &ExitError{Code: exitAuth}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&hostname, "hostname", "h", "", "Check only a specific host")
	cmd.Flags().BoolVarP(&showToken, "show-token", "t", false, "Display the auth token")
	return cmd
}

func newAuthLogoutCmd() *cobra.Command {
	var hostname string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Log out of an IQ Server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if hostname == "" {
				if len(cfg.Hosts) != 1 {
					return usageErr("--hostname required (logged in to %d hosts)", len(cfg.Hosts))
				}
				hostname = cfg.HostNames()[0]
			}
			key, _, err := config.NormalizeHost(hostname)
			if err != nil {
				return err
			}
			h, ok := cfg.Hosts[key]
			if !ok {
				return fmt.Errorf("not logged in to %s", key)
			}
			if err := config.KeyringDelete(key, h.User); err != nil {
				return fmt.Errorf("removing token from the OS keyring: %w", err)
			}
			delete(cfg.Hosts, key)
			if err := cfg.Save(); err != nil {
				return err
			}
			success("Logged out of %s account %s", key, h.User)
			return nil
		},
	}
	cmd.Flags().StringVarP(&hostname, "hostname", "h", "", "The host to log out of")
	return cmd
}

func newAuthTokenCmd() *cobra.Command {
	var hostname string
	cmd := &cobra.Command{
		Use:   "token",
		Short: `Print the credentials st uses, as "code:passcode"`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			_, h, err := cfg.Resolve(hostname)
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, h.User+":"+h.Token)
			return nil
		},
	}
	cmd.Flags().StringVarP(&hostname, "hostname", "h", "", "The host to print the token for")
	return cmd
}

func prompt(label string) string {
	fmt.Fprint(stderr, label)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	return strings.TrimSpace(line)
}
