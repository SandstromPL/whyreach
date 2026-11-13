package platform

import (
	"runtime"
	"testing"
)

func TestDetect(t *testing.T) {
	i := Detect()
	if i.OS != runtime.GOOS || i.Arch != runtime.GOARCH {
		t.Errorf("Detect() = %+v", i)
	}
}
