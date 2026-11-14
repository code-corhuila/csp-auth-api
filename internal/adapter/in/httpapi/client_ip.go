package httpapi

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientAddress is the address the login attempt limit counts (HU-AUTH-005). Behind the gateway, the
// last entry of X-Forwarded-For is the address the gateway itself saw (NGINX appends it); the entries
// before it are whatever the client sent, so they are never used. Without a usable header the peer of
// the connection is used. An empty result means the address is unknown and the request is not limited.
func clientAddress(r *http.Request) string {
	if forwarded := lastForwardedEntry(r.Header.Values("X-Forwarded-For")); forwarded != "" {
		if address, err := netip.ParseAddr(forwarded); err == nil {
			return address.Unmap().String()
		}
	}
	return peerAddress(r.RemoteAddr)
}

// lastForwardedEntry is the last comma-separated entry of the last X-Forwarded-For line.
func lastForwardedEntry(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	entries := strings.Split(lines[len(lines)-1], ",")
	return strings.TrimSpace(entries[len(entries)-1])
}

func peerAddress(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return address.Unmap().String()
}
