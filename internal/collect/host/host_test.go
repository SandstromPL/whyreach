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
