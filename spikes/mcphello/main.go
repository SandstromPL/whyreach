// Command mcphello is the M0 spike for NetDoctor's MCP surface: one read-only
// tool registered with the official Go SDK's typed handler, so the SDK infers
// the input and output JSON schemas and fills structuredContent.
//
// Run it over stdio from an MCP client, for example:
//
//	claude mcp add nd-spike -- /abs/path/to/mcphello
package main

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SandstromPL/netdoctor/spikes/internal/procnet"
)

// ListenersIn is the tool input.
type ListenersIn struct {
	Port int `json:"port,omitempty" jsonschema:"only return listeners on this TCP port; omit or 0 for all"`
}

// Listener is one listening socket.
type Listener struct {
	Proto string `json:"proto" jsonschema:"tcp or tcp6"`
	Addr  string `json:"addr" jsonschema:"bind address and port, e.g. 127.0.0.1:8080"`
}

// ListenersOut is the structured tool output.
type ListenersOut struct {
	Context   string     `json:"context" jsonschema:"where the sockets were read"`
	Listeners []Listener `json:"listeners"`
}

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "netdoctor-spike", Version: "0.0.0-m0"}, nil)
	no := false
	mcp.AddTool(s, &mcp.Tool{
		Name:  "host_listeners",
		Title: "Host TCP listeners",
		Description: "List the TCP sockets listening in the host's network namespace. " +
			"Use it to check whether a service is listening and on which address " +
			"(127.0.0.1 means loopback only).",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			IdempotentHint:  true,
			DestructiveHint: &no,
			OpenWorldHint:   &no,
		},
	}, hostListeners)
	return s
}

func hostListeners(_ context.Context, _ *mcp.CallToolRequest, in ListenersIn) (*mcp.CallToolResult, ListenersOut, error) {
	if in.Port < 0 || in.Port > 65535 {
		return nil, ListenersOut{}, fmt.Errorf("port %d is out of range 0-65535", in.Port)
	}
	socks, err := procnet.Listeners("/proc")
	if err != nil {
		return nil, ListenersOut{}, fmt.Errorf("read listeners: %w", err)
	}
	out := ListenersOut{Context: "host network namespace", Listeners: []Listener{}}
	for _, s := range socks {
		if in.Port != 0 && int(s.Local.Port()) != in.Port {
			continue
		}
		out.Listeners = append(out.Listeners, Listener{Proto: s.Proto, Addr: s.Local.String()})
	}
	slices.SortFunc(out.Listeners, func(a, b Listener) int {
		return strings.Compare(a.Proto+" "+a.Addr, b.Proto+" "+b.Addr)
	})
	// A short text summary for clients that ignore structuredContent.
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: summary(out)}}}, out, nil
}

func summary(out ListenersOut) string {
	if len(out.Listeners) == 0 {
		return "No matching TCP listeners in the " + out.Context + "."
	}
	addrs := make([]string, 0, len(out.Listeners))
	for _, l := range out.Listeners {
		addrs = append(addrs, l.Addr)
	}
	if len(addrs) > 10 {
		addrs = append(addrs[:10], fmt.Sprintf("and %d more", len(out.Listeners)-10))
	}
	return fmt.Sprintf("%d TCP listener(s) in the %s: %s", len(out.Listeners), out.Context, strings.Join(addrs, ", "))
}

func main() {
	// log writes to stderr; stdout is the MCP protocol channel.
	if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
