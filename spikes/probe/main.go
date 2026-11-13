// Command probe is the M0 spike for NetDoctor's probe container (INITIAL.md §3.3).
//
//	probe serve ADDR...   listen on each TCP address and accept forever
//	                      (a stand-in for a distroless service)
//	probe report [--dns NAME]... [--tcp HOST:PORT]... [--timeout 2s] [--proc-dir /proc]
//	                      print what this network namespace looks like, as JSON
//
// The image is FROM scratch, so the binary must not rely on anything inside it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SandstromPL/netdoctor/spikes/internal/procnet"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe serve ADDR... | probe report [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "report":
		err = report(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

// serve listens on every address it can and keeps going if one fails (for
// example when IPv6 is disabled in the container).
func serve(addrs []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	for _, a := range addrs {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			return err
		}
		network := "tcp4" // like most apps binding 0.0.0.0: IPv4 only
		if ap.Addr().Is6() {
			network = "tcp6"
		}
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "probe: listen %s: %v\n", a, err)
			continue
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	<-ctx.Done()
	return nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type dnsResult struct {
	Name    string   `json:"name"`
	Addrs   []string `json:"addrs,omitempty"`
	Outcome string   `json:"outcome"` // ok | not_found | timeout | error
	Error   string   `json:"error,omitempty"`
}

type tcpResult struct {
	Target  string  `json:"target"`
	Addr    string  `json:"addr,omitempty"`
	Outcome string  `json:"outcome"` // connected | refused | timeout | unreachable | reset | resolve_failed | error
	Error   string  `json:"error,omitempty"`
	RTTms   float64 `json:"rtt_ms"`
}

type reportOut struct {
	Hostname   string           `json:"hostname"`
	Netns      string           `json:"netns"`
	UID        int              `json:"uid"`
	CapEff     string           `json:"cap_eff"`
	ResolvConf string           `json:"resolv_conf"`
	Hosts      string           `json:"hosts"`
	Listeners  []procnet.Socket `json:"listeners"`
	ListenErr  string           `json:"listeners_error,omitempty"`
	DNS        []dnsResult      `json:"dns,omitempty"`
	TCP        []tcpResult      `json:"tcp,omitempty"`
}

func report(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var names, targets multiFlag
	fs.Var(&names, "dns", "name to resolve (repeatable)")
	fs.Var(&targets, "tcp", "HOST:PORT to connect to (repeatable)")
	timeout := fs.Duration("timeout", 2*time.Second, "per-check timeout")
	procDir := fs.String("proc-dir", "/proc", `where to read net/tcp{,6} from ("/proc/<pid>" reads another process's netns)`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	out := reportOut{UID: os.Getuid()}
	out.Hostname, _ = os.Hostname()
	out.Netns, _ = os.Readlink("/proc/self/ns/net")
	out.CapEff = capEff()
	out.ResolvConf = readOrErr("/etc/resolv.conf")
	out.Hosts = readOrErr("/etc/hosts")
	if l, err := procnet.Listeners(*procDir); err != nil {
		out.ListenErr = err.Error()
	} else {
		out.Listeners = l
	}
	for _, n := range names {
		out.DNS = append(out.DNS, lookup(n, *timeout))
	}
	for _, t := range targets {
		out.TCP = append(out.TCP, dial(t, *timeout)...)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func lookup(name string, timeout time.Duration) dnsResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	r := dnsResult{Name: name, Outcome: "ok"}
	if err != nil {
		r.Error = err.Error()
		var de *net.DNSError
		switch {
		case errors.As(err, &de) && de.IsNotFound:
			r.Outcome = "not_found"
		case errors.As(err, &de) && de.IsTimeout:
			r.Outcome = "timeout"
		default:
			r.Outcome = "error"
		}
		return r
	}
	for _, a := range addrs {
		r.Addrs = append(r.Addrs, a.String())
	}
	return r
}

func dial(target string, timeout time.Duration) []tcpResult {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return []tcpResult{{Target: target, Outcome: "error", Error: err.Error()}}
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return []tcpResult{{Target: target, Outcome: "error", Error: err.Error()}}
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		r := lookup(host, timeout)
		if r.Outcome != "ok" {
			return []tcpResult{{Target: target, Outcome: "resolve_failed", Error: r.Error}}
		}
		for _, s := range r.Addrs {
			addrs = append(addrs, netip.MustParseAddr(s))
		}
	}
	if len(addrs) > 4 {
		addrs = addrs[:4]
	}
	var out []tcpResult
	for _, a := range addrs {
		ap := netip.AddrPortFrom(a, uint16(port)).String()
		d := net.Dialer{Timeout: timeout}
		start := time.Now()
		c, err := d.Dial("tcp", ap)
		r := tcpResult{Target: target, Addr: ap, RTTms: float64(time.Since(start).Microseconds()) / 1000}
		if err == nil {
			_ = c.Close()
			r.Outcome = "connected"
		} else {
			r.Outcome, r.Error = classify(err), err.Error()
		}
		out = append(out, r)
	}
	return out
}

func classify(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	default:
		return "error"
	}
}

func capEff() string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "error: " + err.Error()
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return "unknown"
}

func readOrErr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "error: " + err.Error()
	}
	return string(b)
}
