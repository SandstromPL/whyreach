package host

import "testing"

func TestAddrs(t *testing.T) {
	h, err := Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for i, ifc := range h.Interfaces {
		if i > 0 && h.Interfaces[i-1].Name >= ifc.Name {
			t.Errorf("interfaces are not sorted: %s before %s", h.Interfaces[i-1].Name, ifc.Name)
		}
		if len(ifc.Addrs) == 0 {
			t.Errorf("%s has no addresses but is listed", ifc.Name)
		}
		for _, p := range ifc.Addrs {
			if p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
				t.Errorf("%s: %s should be left out", ifc.Name, p)
			}
		}
	}
}

func TestIsDockerBridge(t *testing.T) {
	for name, want := range map[string]bool{
		"docker0": true, "br-0123456789ab": true, "br-0123456789AB": false, "br-0123": false,
		"eth0": false, "lo": false, "docker1": false, "br-0123456789abc": false,
	} {
		if got := IsDockerBridge(name); got != want {
			t.Errorf("IsDockerBridge(%q) = %v, want %v", name, got, want)
		}
	}
}
