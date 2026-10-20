package config

import (
	"errors"
	"time"

	"github.com/zalando/go-keyring"
)

// Tokens live in the OS keyring (macOS Keychain, Windows Credential Manager,
// Linux Secret Service) under service "st:<host>", like bb and gh.
// Host.Token in config.json is only used for insecure storage.

const keyringTimeout = 3 * time.Second

var errKeyringTimeout = errors.New("timed out waiting for the OS keyring")

func service(host string) string { return "st:" + host }

// withTimeout guards against keyrings that block (e.g. a locked Secret Service
// waiting for an unlock prompt that never comes on a headless machine).
func withTimeout[T any](f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(keyringTimeout):
		var zero T
		return zero, errKeyringTimeout
	}
}

func KeyringSet(host, user, token string) error {
	_, err := withTimeout(func() (struct{}, error) {
		return struct{}{}, keyring.Set(service(host), user, token)
	})
	return err
}

func KeyringGet(host, user string) (string, error) {
	return withTimeout(func() (string, error) { return keyring.Get(service(host), user) })
}

// KeyringDelete removes the host's token; a missing entry is not an error.
func KeyringDelete(host, user string) error {
	_, err := withTimeout(func() (struct{}, error) {
		return struct{}{}, keyring.Delete(service(host), user)
	})
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
