package webhook

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"syscall"
)

// Where a webhook may be delivered.
//
// A webhook URL is written by an administrator, but the registry is what
// fetches it — so a URL naming an address the registry can reach and its author
// cannot turns the registry into a way in: cloud metadata services, a database
// admin port, anything else listening on the host or the private network. The
// receiver does not even have to respond usefully, since the request itself is
// the effect.
//
// Internal destinations are refused unless REGISTRY_WEBHOOK_ALLOW_INTERNAL says
// otherwise, which is the setting for a receiver that genuinely does live on the
// same private network.

// ErrInternalDestination is returned for a URL that resolves somewhere the
// registry will not deliver to.
type ErrInternalDestination struct {
	Host string
	Addr string
}

func (e *ErrInternalDestination) Error() string {
	if e.Addr != "" && e.Addr != e.Host {
		return fmt.Sprintf("%s resolves to %s, which is not a public address; "+
			"set REGISTRY_WEBHOOK_ALLOW_INTERNAL=true to deliver there", e.Host, e.Addr)
	}
	return fmt.Sprintf("%s is not a public address; "+
		"set REGISTRY_WEBHOOK_ALLOW_INTERNAL=true to deliver there", e.Host)
}

// ValidateURL checks the shape of a webhook URL, and — when internal delivery
// is not allowed — that its host does not resolve anywhere private.
//
// Resolution here is a courtesy: it catches a mistake when the webhook is
// created rather than silently at delivery time. It is not the control. DNS can
// answer differently a second later, so the address is checked again as the
// connection is made, which is the only check that cannot be raced.
func ValidateURL(ctx context.Context, raw string, allowInternal bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("url must name a host")
	}
	if allowInternal {
		return nil
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if !isPublic(ip) {
			return &ErrInternalDestination{Host: host}
		}
		return nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		// A name that does not resolve now may resolve later; the dial-time
		// check is what settles it. Refusing here would block a receiver that
		// is simply not up yet.
		return nil
	}
	for _, addr := range addrs {
		if !isPublic(addr) {
			return &ErrInternalDestination{Host: host, Addr: addr.String()}
		}
	}
	return nil
}

// dialGuard returns a Control function for a net.Dialer that refuses to
// complete a connection to a non-public address.
//
// This runs after the name has been resolved and immediately before the socket
// is connected, which is what closes the gap a DNS answer that changes between
// the check and the connection would otherwise open.
func dialGuard(allowInternal bool) func(network, address string, c syscall.RawConn) error {
	if allowInternal {
		return nil
	}
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("webhook: cannot check destination %q", address)
		}
		if !isPublic(ip) {
			return &ErrInternalDestination{Host: host}
		}
		return nil
	}
}

// isPublic reports whether an address is one the registry will deliver to when
// internal destinations are refused.
//
// Everything with a special meaning is excluded rather than just RFC 1918: the
// loopback interface, link-local — which is where cloud metadata services live
// at 169.254.169.254 — unique local addresses, the unspecified address,
// multicast, and IPv4-mapped forms of any of them.
func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(),
		ip.IsLoopback(),
		ip.IsPrivate(),
		ip.IsLinkLocalUnicast(),
		ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(),
		ip.IsMulticast(),
		ip.IsUnspecified():
		return false
	}
	// 100.64.0.0/10, shared address space — carrier NAT and the range Tailscale
	// hands out, so it is reachable-but-internal in exactly the way that
	// matters here.
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	return true
}
