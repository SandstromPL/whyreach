//go:build linux

package main

import (
	"encoding/binary"
	"testing"
)

// runFilter interprets the classic BPF instructions the filter uses on a
// struct seccomp_data with the given arch, syscall number and first
// argument.
func runFilter(t *testing.T, prog []byte, arch, nr uint32, arg0 uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.NativeEndian.PutUint32(data[0:], nr)
	binary.NativeEndian.PutUint32(data[4:], arch)
	binary.NativeEndian.PutUint64(data[16:], arg0)
	var a uint32
	for pc := 0; pc < len(prog)/8; pc++ {
		ins := prog[pc*8:]
		code := binary.NativeEndian.Uint16(ins)
		jt, jf := int(ins[2]), int(ins[3])
		k := binary.NativeEndian.Uint32(ins[4:])
		switch code {
		case bpfLdWAbs:
			a = binary.NativeEndian.Uint32(data[k:])
		case bpfJeqK:
			if a == k {
				pc += jt
			} else {
				pc += jf
			}
		case bpfJgeK:
			if a >= k {
				pc += jt
			} else {
				pc += jf
			}
		case bpfRetK:
			return k
		default:
			t.Fatalf("instruction %d: unknown code %#x", pc, code)
		}
	}
	t.Fatal("the program ran off its end")
	return 0
}

func TestSeccompFilter(t *testing.T) {
	for _, tc := range []struct {
		goarch                          string
		arch, socket, keyctl, otherArch uint32
	}{
		{"amd64", 0xc000003e, 41, 250, 0x40000003},
		{"arm64", 0xc00000b7, 198, 219, 0x40000028},
	} {
		prog, err := seccompFilter(tc.goarch)
		if err != nil {
			t.Fatal(err)
		}
		checks := []struct {
			name     string
			arch, nr uint32
			arg0     uint64
			want     uint32
		}{
			{"socket(AF_UNIX)", tc.arch, tc.socket, 1, retErrno | eperm},
			{"socket(AF_INET)", tc.arch, tc.socket, 2, retAllow},
			{"socket(AF_NETLINK)", tc.arch, tc.socket, 16, retAllow},
			{"io_uring_setup", tc.arch, 425, 0, retErrno | eperm},
			{"keyctl", tc.arch, tc.keyctl, 0, retErrno | eperm},
			{"another syscall", tc.arch, 0, 1, retAllow},
			{"another ABI", tc.otherArch, tc.socket, 1, retKill},
		}
		if tc.goarch == "amd64" {
			checks = append(checks, struct {
				name     string
				arch, nr uint32
				arg0     uint64
				want     uint32
			}{"the x32 ABI", tc.arch, 0x40000000 | 41, 1, retKill})
		}
		for _, c := range checks {
			if got := runFilter(t, prog, c.arch, c.nr, c.arg0); got != c.want {
				t.Errorf("%s %s: %#x, want %#x", tc.goarch, c.name, got, c.want)
			}
		}
	}
	if _, err := seccompFilter("riscv64"); err == nil {
		t.Error("an architecture without a filter must refuse to run")
	}
}
