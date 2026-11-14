package bench

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// fakeDocker answers the few Engine API paths the proxy reads, with one
// lab container and one of the owner's.
func fakeDocker(t *testing.T) http.Handler {
	t.Helper()
	lab := map[string]any{"Id": "aaa", "Name": "/whyreach-lab-1a2b3c-api-1", "Image": "sha256:lab",
		"Config": map[string]any{"Labels": map[string]string{"com.docker.compose.project": "whyreach-lab-1a2b3c"}}}
	other := map[string]any{"Id": "bbb", "Name": "/billing-db", "Image": "sha256:pg",
		"Config": map[string]any{"Labels": map[string]string{"com.docker.compose.project": "billing"}}}
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) {
		j(w, []map[string]any{
			{"Id": "aaa", "Names": []string{"/whyreach-lab-1a2b3c-api-1"}, "ImageID": "sha256:lab", "Labels": map[string]string{"com.docker.compose.project": "whyreach-lab-1a2b3c"}},
			{"Id": "bbb", "Names": []string{"/billing-db"}, "ImageID": "sha256:pg", "Labels": map[string]string{"com.docker.compose.project": "billing"}},
		})
	})
	mux.HandleFunc("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("id") {
		case "aaa", "whyreach-lab-1a2b3c-api-1":
			j(w, lab)
		case "bbb", "billing-db":
			j(w, other)
		default:
			http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		}
	})
	mux.HandleFunc("GET /containers/{id}/logs", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "log line\n") })
	mux.HandleFunc("POST /containers/{id}/wait", func(w http.ResponseWriter, _ *http.Request) { j(w, map[string]int{"StatusCode": 0}) })
	mux.HandleFunc("GET /networks", func(w http.ResponseWriter, _ *http.Request) {
		j(w, []map[string]any{
			{"Name": "bridge", "Containers": map[string]any{"aaa": map[string]string{"Name": "whyreach-lab-1a2b3c-api-1"}, "bbb": map[string]string{"Name": "billing-db"}}},
			{"Name": "whyreach-lab-1a2b3c_default"},
			{"Name": "billing_network_x"},
		})
	})
	mux.HandleFunc("GET /networks/{id}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("id") {
		case "bridge":
			j(w, map[string]any{"Name": "bridge", "Containers": map[string]any{"aaa": map[string]string{"Name": "whyreach-lab-1a2b3c-api-1"}, "bbb": map[string]string{"Name": "billing-db"}}})
		case "billing_network_x":
			j(w, map[string]any{"Name": "billing_network_x"})
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	})
	mux.HandleFunc("GET /images/{name}/json", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("name") {
		case "python:3.13-slim":
			j(w, map[string]any{"Id": "sha256:lab", "RepoTags": []string{"python:3.13-slim"}})
		case "postgres:16":
			j(w, map[string]any{"Id": "sha256:pg", "RepoTags": []string{"postgres:16"}})
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	})
	mux.HandleFunc("GET /info", func(w http.ResponseWriter, _ *http.Request) {
		j(w, map[string]any{"Name": "host", "HttpProxy": "http://user:secret@proxy:3128"})
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Type":"container","Action":"die","Actor":{"ID":"aaa","Attributes":{"name":"whyreach-lab-1a2b3c-api-1"}}}`+"\n")
		_, _ = io.WriteString(w, `{"Type":"container","Action":"die","Actor":{"ID":"bbb","Attributes":{"name":"billing-db"}}}`+"\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the proxy forwarded %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusTeapot)
	})
	// The daemon serves every path with and without the API version.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = versionPrefix.ReplaceAllString(r.URL.Path, "")
		mux.ServeHTTP(w, r)
	})
}

type handlerTransport struct{ h http.Handler }

func (ht handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	r2 := r.Clone(r.Context())
	r2.RequestURI = r.URL.RequestURI()
	ht.h.ServeHTTP(rec, r2)
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

func TestProxy(t *testing.T) {
	p := newProxy(handlerTransport{fakeDocker(t)})
	srv := httptest.NewServer(p)
	defer srv.Close()
	do := func(method, path string) (int, string) {
		req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	tests := []struct {
		method, path string
		status       int
		contains     []string
		lacks        []string
		decision     string
	}{
		{"GET", "/v1.51/containers/json?all=1", 200, []string{"whyreach-lab-1a2b3c-api-1"}, []string{"billing"}, DecisionRead},
		{"GET", "/v1.51/containers/whyreach-lab-1a2b3c-api-1/json", 200, []string{"whyreach-lab-1a2b3c"}, nil, DecisionRead},
		{"GET", "/v1.51/containers/billing-db/json", 404, []string{"No such container"}, []string{"billing\""}, DecisionHidden},
		{"GET", "/v1.51/containers/aaa/logs?stdout=1", 200, []string{"log line"}, nil, DecisionRead},
		{"GET", "/v1.51/containers/bbb/logs", 404, nil, []string{"log line"}, DecisionHidden},
		{"POST", "/v1.51/containers/aaa/wait", 200, []string{"StatusCode"}, nil, DecisionRead},
		{"POST", "/v1.51/containers/aaa/exec", 403, []string{"read-only view", "POST /containers/aaa/exec"}, nil, DecisionRefused},
		{"POST", "/v1.51/containers/create", 403, []string{"read-only view"}, nil, DecisionRefused},
		{"DELETE", "/v1.51/containers/aaa", 403, nil, nil, DecisionRefused},
		{"POST", "/v1.51/networks/create", 403, nil, nil, DecisionRefused},
		{"GET", "/v1.51/containers/aaa/attach/ws", 403, nil, nil, DecisionRefused},
		{"GET", "/v1.51/networks", 200, []string{"whyreach-lab-1a2b3c_default", "bridge", "whyreach-lab-1a2b3c-api-1"}, []string{"billing"}, DecisionRead},
		{"GET", "/v1.51/networks/bridge", 200, []string{"whyreach-lab-1a2b3c-api-1"}, []string{"billing-db"}, DecisionRead},
		{"GET", "/v1.51/networks/billing_network_x", 404, nil, []string{"billing\""}, DecisionHidden},
		{"GET", "/v1.51/images/python:3.13-slim/json", 200, []string{"python"}, nil, DecisionRead},
		{"GET", "/v1.51/images/postgres:16/json", 200, nil, nil, DecisionRead}, // pg is used by no lab container…
		{"GET", "/v1.51/info", 200, []string{`"HttpProxy":""`}, []string{"secret"}, DecisionRead},
		{"GET", "/v1.51/events?since=1", 200, []string{"whyreach-lab-1a2b3c-api-1"}, []string{"billing"}, DecisionRead},
		{"GET", "/v1.51/system/df", 404, []string{"isn't available"}, nil, DecisionUnsupported},
	}
	// …so postgres is hidden after all: fix the expectation in place.
	tests[15].status, tests[15].decision = 404, DecisionHidden
	for _, tc := range tests {
		status, body := do(tc.method, tc.path)
		if status != tc.status {
			t.Errorf("%s %s: status %d, want %d: %s", tc.method, tc.path, status, tc.status, body)
		}
		for _, s := range tc.contains {
			if !strings.Contains(body, s) {
				t.Errorf("%s %s: body lacks %q: %s", tc.method, tc.path, s, body)
			}
		}
		for _, s := range tc.lacks {
			if strings.Contains(body, s) {
				t.Errorf("%s %s: body shows %q: %s", tc.method, tc.path, s, body)
			}
		}
		evs := p.Take()
		if len(evs) != 1 || evs[0].Decision != tc.decision {
			t.Errorf("%s %s: events %+v, want one %s", tc.method, tc.path, evs, tc.decision)
		}
	}
}

func TestProxyEventFields(t *testing.T) {
	p := newProxy(handlerTransport{fakeDocker(t)})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1.51/containers/aaa/restart?t=1", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)
	evs := p.Take()
	if len(evs) != 1 {
		t.Fatalf("events: %+v", evs)
	}
	evs[0].Time = evs[0].Time.UTC().Truncate(0)
	want := ProxyEvent{Method: "POST", Path: "/containers/aaa/restart", Query: "t=1", Decision: DecisionRefused, Status: 403}
	got := evs[0]
	got.Time = want.Time
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("event (-want +got):\n%s", diff)
	}
	if !evs[0].Refused() {
		t.Error("Refused() is false for a refused write")
	}
	if len(p.Take()) != 0 {
		t.Error("Take must forget what it returned")
	}
}
