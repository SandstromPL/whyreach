// Package target parses the "from" and "to" arguments (INITIAL.md §4.3) and
// holds the probe-target policy that every address whyreach connects to must
// pass (§4.9). It rejects anything that is not exactly one host:port.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Error is a rejected argument. Policy errors are denials of a well-formed
// target (a link-local or cloud-metadata address); the rest are syntax errors.
type Error struct {
	Arg    string // "from" or "to"
	Input  string
	Reason string
	Policy bool
}

func (e *Error) Error() string {
	return fmt.Sprintf("invalid %s %q: %s", e.Arg, e.Input, e.Reason)
}

// MaskArg masks credentials in an argument as given (see MaskCredentials):
// in a destination ("to", "target") always; in a source or scope unless it
// is service:<name>@<project>, whose "@" names a Compose project; in
// anything else (an error message, an answer) only in a URL.
func MaskArg(arg, s string) string {
	switch {
	case arg == "to" || arg == "target" || strings.Contains(s, "://"):
		return MaskCredentials(s)
	case arg == "from" || arg == "scope":
		if strings.HasPrefix(strings.TrimSpace(s), FromService+":") {
			return s
		}
		return MaskCredentials(s)
	default:
		return s
	}
}

// MaskCredentials hides what a URL-like argument may carry besides the
// address: the userinfo before an "@" and the query
// ("postgres://app:s3cr3t@db:5432/app?sslpassword=x" becomes
// "postgres://***@db:5432/app?***"). An agent may pass a connection string
// as it is; its password must never reach an error, a log or the audit.
func MaskCredentials(s string) string {
	prefix, rest := "", s
	if i := strings.Index(s, "://"); i >= 0 {
		prefix, rest = s[:i+3], s[i+3:]
	}
	auth, tail := rest, ""
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		auth, tail = rest[:j], rest[j:]
	}
	if at := strings.LastIndex(auth, "@"); at >= 0 {
		auth = "***" + auth[at:]
	}
	if q := strings.IndexAny(tail, "?#"); q >= 0 {
		tail = tail[:q+1] + "***"
	}
	return prefix + auth + tail
}

// From kinds.
const (
	FromHost      = "host"
	FromContainer = "container"
	FromService   = "service"
)

// From is where a connection starts.
type From struct {
	Kind    string // host, container or service
	Name    string // container name or ID, or Compose service name
	Project string // Compose project, for service; optional
}

// String is the canonical form: "host", "container:worker", "service:worker@shop".
func (f From) String() string {
	switch f.Kind {
	case FromContainer:
		return "container:" + f.Name
	case FromService:
		if f.Project != "" {
			return "service:" + f.Name + "@" + f.Project
		}
		return "service:" + f.Name
	default:
		return FromHost
	}
}

var (
	// Docker container names and IDs: [a-zA-Z0-9][a-zA-Z0-9_.-]*.
	containerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$`)
	// Compose project names: lowercase letters, digits, dashes and underscores.
	projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,254}$`)
	// A host name: labels of letters, digits, '-' and '_' (container names may contain '_').
	hostName = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)*\.?$`)
)

// ParseFrom parses "host", "container:<name|id>" or "service:<name>[@<project>]".
// An empty string means the host.
func ParseFrom(s string) (From, error) {
	in := strings.TrimSpace(s)
	bad := func(reason string) (From, error) {
		return From{}, &Error{Arg: "from", Input: MaskArg("from", s), Reason: reason}
	}
	if in == "" || in == FromHost {
		return From{Kind: FromHost}, nil
	}
	kind, rest, ok := strings.Cut(in, ":")
	if !ok {
		return bad("want host, container:<name> or service:<name>[@<project>]")
	}
	switch kind {
	case FromContainer:
		name := strings.TrimPrefix(rest, "/")
		if !containerName.MatchString(name) {
			return bad("not a container name or ID")
		}
		return From{Kind: FromContainer, Name: name}, nil
	case FromService:
		name, project, _ := strings.Cut(rest, "@")
		if !containerName.MatchString(name) {
			return bad("not a Compose service name")
		}
		if project != "" && !projectName.MatchString(project) {
			return bad("not a Compose project name")
		}
		return From{Kind: FromService, Name: name, Project: project}, nil
	default:
		return bad("want host, container:<name> or service:<name>[@<project>]")
	}
}

// ParseTo parses "<host>:<port>" or "tcp://<host>:<port>". The host may be a
// name, an IPv4 address or a bracketed IPv6 address. CIDRs, ranges, lists,
// wildcards, other schemes, credentials and blocked addresses are rejected.
func ParseTo(s string) (evidence.Target, error) {
	in := strings.TrimSpace(s)
	bad := func(reason string) (evidence.Target, error) {
		return evidence.Target{}, &Error{Arg: "to", Input: MaskCredentials(s), Reason: reason}
	}
	if scheme, rest, ok := strings.Cut(in, "://"); ok {
		if !strings.EqualFold(scheme, "tcp") {
			return bad("only tcp:// targets are supported")
		}
		in = rest
	}
	switch {
	case in == "":
		return bad("want host:port")
	case strings.Contains(in, "@"):
		return bad("credentials are not allowed in a target")
	case strings.ContainsAny(in, "*?"):
		return bad("wildcards are not allowed: one host:port per call")
	case strings.ContainsAny(in, ", "):
		return bad("lists are not allowed: one host:port per call")
	case strings.Contains(in, "/"):
		return bad("CIDRs and paths are not allowed: one host:port per call")
	}
	host, portStr, err := net.SplitHostPort(in)
	if err != nil {
		return bad("want host:port, with IPv6 addresses in brackets")
	}
	if strings.Contains(portStr, "-") {
		return bad("port ranges are not allowed: one host:port per call")
	}
	if addressRange(host) {
		return bad("address ranges are not allowed: one host:port per call")
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return bad("the port must be a number from 1 to 65535")
	}
	if strings.Contains(host, "%") {
		return bad("IPv6 zones are not supported")
	}
	if host == "" {
		return bad("missing host")
	}
	if len(host) > 253 {
		return bad("a host name has at most 253 characters")
	}
	if _, err := netip.ParseAddr(host); err != nil && !hostName.MatchString(host) {
		return bad("not a host name or IP address")
	}
	class, addr := evidence.ClassifyHost(host)
	if addr.IsValid() {
		host = addr.String()
		if reason, blocked := Blocked(addr); blocked {
			return evidence.Target{}, &Error{Arg: "to", Input: MaskCredentials(s), Reason: reason, Policy: true}
		}
	} else {
		host = strings.ToLower(host)
	}
	return evidence.Target{Host: host, Port: uint16(port), Proto: "tcp", Class: class, Addr: addr}, nil
}

// addressRange reports whether host is written as a range of addresses, such
// as "10.0.0.1-5", "10.0.0-3.1", "10.0.0.1-10.0.0.5" or the IPv6 "fd00::1-5":
// a hyphen inside digits and dots, or inside hex digits and colons. The
// host-name grammar would otherwise accept the IPv4 forms as one name and
// look it up. A Docker container could in theory carry such a name; refusing
// it is the safer reading of "one host:port per call".
func addressRange(host string) bool {
	h := strings.TrimSuffix(host, ".")
	if !strings.Contains(h, "-") || strings.HasPrefix(h, "-") || strings.HasSuffix(h, "-") {
		return false
	}
	if strings.Contains(h, ":") { // only IPv6 literals have colons
		return onlyOf(h, "0123456789abcdefABCDEF:.-")
	}
	return strings.Contains(h, ".") && onlyOf(h, "0123456789.-")
}

// onlyOf reports whether every character of s is in set.
func onlyOf(s, set string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return !strings.ContainsRune(set, r) }) < 0
}

var (
	awsMetadataV6     = netip.MustParseAddr("fd00:ec2::254")
	alibabaMetadataV4 = netip.MustParseAddr("100.100.100.200")
)

// Blocked reports whether whyreach refuses to connect to addr: link-local
// addresses (which include the 169.254.169.254 cloud-metadata service) and
// the other well-known metadata addresses. It applies to literal targets and
// to every address a name resolves to.
func Blocked(addr netip.Addr) (reason string, blocked bool) {
	a := addr.Unmap()
	switch {
	case a.IsLinkLocalUnicast():
		return "link-local addresses (including cloud metadata at 169.254.169.254) are blocked by policy", true
	case a == awsMetadataV6, a == alibabaMetadataV4:
		return "cloud-metadata addresses are blocked by policy", true
	case a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "multicast and broadcast addresses are not connection targets", true
	default:
		return "", false
	}
}

// Scope kinds for inspect_environment.
const (
	ScopeHost      = "host"
	ScopeContainer = "container"
	ScopeService   = "service"
	ScopeNetwork   = "network"
)

// Scope is what to inspect: the host, one container (by name, ID or Compose
// service) or one Docker network.
type Scope struct {
	Kind    string
	Name    string
	Project string // for service
}

// String is the canonical form: "host", "container:api", "network:shop_default".
func (s Scope) String() string {
	switch s.Kind {
	case ScopeContainer, ScopeService:
		return From(s).String()
	case ScopeNetwork:
		return "network:" + s.Name
	default:
		return ScopeHost
	}
}

// ParseScope parses "host", "container:<name|id>", "service:<name>[@<project>]"
// or "network:<name|id>".
func ParseScope(s string) (Scope, error) {
	in := strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(in, "network:"); ok {
		if !containerName.MatchString(rest) {
			return Scope{}, &Error{Arg: "scope", Input: MaskArg("scope", s), Reason: "not a network name or ID"}
		}
		return Scope{Kind: ScopeNetwork, Name: rest}, nil
	}
	if in == "" {
		return Scope{}, &Error{Arg: "scope", Input: MaskArg("scope", s), Reason: "want host, container:<name>, service:<name>[@<project>] or network:<name>"}
	}
	f, err := ParseFrom(in)
	if err != nil {
		var te *Error
		if errors.As(err, &te) {
			te.Arg = "scope"
			te.Reason = "want host, container:<name>, service:<name>[@<project>] or network:<name>"
		}
		return Scope{}, err
	}
	return Scope(f), nil
}

// ParseName parses a name to look up: a host name or an IP address, nothing
// else (no port, no scheme, no wildcard).
func ParseName(s string) (string, error) {
	in := strings.TrimSuffix(strings.TrimSpace(s), ".")
	bad := func(reason string) (string, error) {
		return "", &Error{Arg: "target", Input: MaskCredentials(s), Reason: reason}
	}
	if in == "" {
		return bad("want a host name to look up")
	}
	if a, err := netip.ParseAddr(in); err == nil {
		return a.Unmap().String(), nil
	}
	if addressRange(in) {
		return bad("address ranges are not allowed: give one name or address")
	}
	if !hostName.MatchString(in) {
		return bad("not a host name: give the name alone, without a port or scheme")
	}
	return strings.ToLower(in), nil
}
