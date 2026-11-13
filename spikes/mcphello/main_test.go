package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect wires the spike server to an in-memory client session.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := t.Context()
	serverT, clientT := mcp.NewInMemoryTransports()
	if _, err := newServer().Connect(ctx, serverT, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "spike-test", Version: "0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestToolIsAdvertisedWithSchemasAndAnnotations(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 1 {
		t.Fatalf("got %d tools, want 1", len(res.Tools))
	}
	tool := res.Tools[0]
	out, err := json.Marshal(tool.OutputSchema)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"listeners"`) {
		t.Errorf("output schema was not inferred from ListenersOut: %s", out)
	}
	in, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(in), "only return listeners on this TCP port") {
		t.Errorf("input schema lacks the jsonschema tag description: %s", in)
	}
	if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
		t.Errorf("annotations = %+v, want readOnlyHint=true", tool.Annotations)
	}
}

func TestCallReturnsTextAndStructuredContent(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "host_listeners", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	var out ListenersOut
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Context == "" {
		t.Fatalf("structuredContent did not round-trip into ListenersOut: %s (%v)", b, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("got %d content blocks, want 1 (our text summary)", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, "host network namespace") {
		t.Errorf("text content = %#v, want our summary", res.Content[0])
	}
}

func TestBadInputIsVisibleToTheModel(t *testing.T) {
	cs := connect(t)
	tests := map[string]map[string]any{
		"out of range (handler error)":   {"port": 70000},
		"wrong type (schema validation)": {"port": "eighty"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "host_listeners", Arguments: args})
			switch {
			case err != nil:
				t.Logf("reported as a protocol error: %v", err)
			case res.IsError:
				t.Logf("reported as a tool error (isError=true): %v", res.Content)
			default:
				t.Errorf("bad input %v was accepted", args)
			}
		})
	}
}
