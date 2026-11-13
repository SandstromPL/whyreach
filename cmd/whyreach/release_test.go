package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleaseMetadataAgrees: the MCP Registry checks that the image carries
// the server's name, so server.json, the Dockerfile and .goreleaser.yaml
// must name the same server and image, and server.json's package must be
// the version it describes.
func TestReleaseMetadataAgrees(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	var s struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Packages []struct {
			RegistryType string `json:"registryType"`
			Identifier   string `json:"identifier"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(read("server.json")), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Packages) != 1 || s.Packages[0].RegistryType != "oci" {
		t.Fatalf("packages = %+v", s.Packages)
	}
	image, tag, _ := strings.Cut(s.Packages[0].Identifier, ":")
	if tag != s.Version {
		t.Errorf("server.json is version %s, its image tag %s", s.Version, tag)
	}
	dockerfile, goreleaser := read("Dockerfile"), read(".goreleaser.yaml")
	if !strings.Contains(dockerfile, `io.modelcontextprotocol.server.name="`+s.Name+`"`) {
		t.Errorf("the Dockerfile doesn't label the image %s", s.Name)
	}
	if !strings.Contains(goreleaser, "io.modelcontextprotocol.server.name: "+s.Name) || !strings.Contains(goreleaser, "- "+image+"\n") {
		t.Errorf(".goreleaser.yaml doesn't build %s labeled %s", image, s.Name)
	}
}
