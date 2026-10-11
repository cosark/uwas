package server

import (
	"net"
	"strings"
)

// maintenanceAllows reports whether a client may bypass a domain's maintenance
// page. An entry is an address or a CIDR range, the forms every other IP list
// accepts. It was compared as a string against the peer address, so a range
// ("192.0.2.0/24"), a differently written IPv6 address ("0:0:0:0:0:0:0:1") or
// an IPv4-mapped one never matched and the operator was shut out of the site
// they were maintaining (F15900).
func maintenanceAllows(allowed []string, client string) bool {
	ip := net.ParseIP(client)
	for _, entry := range allowed {
		if entry == client {
			return true
		}
		if ip == nil {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, n, err := net.ParseCIDR(entry); err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if a := net.ParseIP(entry); a != nil && a.Equal(ip) {
			return true
		}
	}
	return false
}
