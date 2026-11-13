// Package procnet parses the kernel's /proc/net/tcp and /proc/net/tcp6
// socket tables (format: Documentation/networking/proc_net_tcp.rst).
//
// M0 spike code. M1 may promote it to internal/probe.
package procnet

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Socket is one row of /proc/net/tcp or /proc/net/tcp6.
type Socket struct {
	Proto string         `json:"proto"` // "tcp" or "tcp6"
	Local netip.AddrPort `json:"local"`
	State string         `json:"state"` // "LISTEN", "ESTABLISHED", …
	Inode uint64         `json:"inode"`
}

var states = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}

// Parse reads a table in /proc/net/tcp format. proto labels the rows.
func Parse(r io.Reader, proto string) ([]Socket, error) {
	var out []Socket
	sc := bufio.NewScanner(r)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, err := parseAddrPort(fields[1])
		if err != nil {
			return nil, fmt.Errorf("parse local address %q: %w", fields[1], err)
		}
		state, ok := states[fields[3]]
		if !ok {
			state = fields[3]
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse inode %q: %w", fields[9], err)
		}
		out = append(out, Socket{Proto: proto, Local: local, State: state, Inode: inode})
	}
	return out, sc.Err()
}

// parseAddrPort decodes "0100007F:1F90" (127.0.0.1:8080). The kernel prints
// each 32-bit word of the address as a host-endian integer, so every word is
// converted back to network byte order with the machine's native endianness.
func parseAddrPort(s string) (netip.AddrPort, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("missing port")
	}
	raw, err := hex.DecodeString(addrHex)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(raw) != 4 && len(raw) != 16 {
		return netip.AddrPort{}, fmt.Errorf("unexpected address length %d", len(raw))
	}
	b := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(b[i:i+4], binary.BigEndian.Uint32(raw[i:i+4]))
	}
	addr, _ := netip.AddrFromSlice(b)
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// Listeners returns the listening TCP sockets of the network namespace that
// procDir belongs to: "/proc" for the caller's own netns, "/proc/<pid>" for
// the netns of another process. A missing tcp6 table (IPv6 disabled) is not
// an error.
func Listeners(procDir string) ([]Socket, error) {
	var out []Socket
	for _, proto := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procDir, "net", proto))
		if err != nil {
			if proto == "tcp6" && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		socks, err := Parse(f, proto)
		_ = f.Close() // read-only file: a close error changes nothing
		if err != nil {
			return nil, err
		}
		for _, s := range socks {
			if s.State == "LISTEN" {
				out = append(out, s)
			}
		}
	}
	return out, nil
}
