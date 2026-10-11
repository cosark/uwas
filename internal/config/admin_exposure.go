package config

import (
	"fmt"
	"net"
	"strings"
)

// weakAdminKeys are placeholder / example admin keys that ship in docs,
// .env.example and docker-compose.yml. Operators routinely leave them in
// place, so they must never guard a publicly bound admin API, and a value
// anyone can look up must never be the secret SFTP passwords derive from.
var weakAdminKeys = map[string]bool{
	"please-change-this-admin-key": true,
	"changeme":                     true,
	"change-me":                    true,
	"change_me":                    true,
	"admin":                        true,
	"password":                     true,
	"secret":                       true,
	"uwas":                         true,
	"test":                         true,
}

// IsWeakAdminKey reports whether key is a well-known placeholder value.
func IsWeakAdminKey(key string) bool {
	return weakAdminKeys[strings.ToLower(strings.TrimSpace(key))]
}

// IsLoopbackListenAddr reports whether the host part of a "host:port" listen
// address binds only to loopback. A bare ":port" or "0.0.0.0:port" binds to
// every interface and is not loopback.
func IsLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// AdminExposureError reports why an admin API listening on addr must not run
// with this key and multi-user setting, or nil when it may: a public listener
// with no credentials exposes the whole API to anyone, and one behind a
// well-known placeholder key exposes it to anyone who guesses. The admin API
// refuses to bind on it, and the live paths that can reach it later (a
// reload, a settings update) must refuse it too, because the listener stays
// bound while the key changes under it (F16200).
func AdminExposureError(addr, apiKey string, multiUser bool) error {
	if addr == "" {
		addr = "127.0.0.1:9443"
	}
	if IsLoopbackListenAddr(addr) {
		return nil
	}
	if apiKey == "" && !multiUser {
		return fmt.Errorf(
			"admin API listen address %q exposes the API without authentication; "+
				"either set global.admin.api_key (or enable global.users.enabled) or "+
				"bind to 127.0.0.1 / ::1", addr)
	}
	if IsWeakAdminKey(apiKey) {
		return fmt.Errorf(
			"admin API listen address %q is public but global.admin.api_key is a well-known "+
				"placeholder value; set a strong, unique key (e.g. `openssl rand -hex 24`) "+
				"or bind to 127.0.0.1 / ::1", addr)
	}
	return nil
}
