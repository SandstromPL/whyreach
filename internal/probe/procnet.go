package probe

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/SandstromPL/whyreach/internal/evidence"
)

// stateListen is the TCP_LISTEN state in /proc/net/tcp{,6}.
const stateListen = "0A"

// ParseListeners reads a socket table in /proc/net/tcp format and returns
// its listening sockets. proto ("tcp" or "tcp6") labels them. The format is
// documented in the kernel's Documentation/networking/proc_net_tcp.rst.
func ParseListeners(r io.Reader, proto string) ([]evidence.Socket, error) {
	var out []evidence.Socket
	sc := bufio.NewScanner(r)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] != stateListen {
			continue
		}
		local, err := parseHexAddrPort(fields[1])
		if err != nil {
			return nil, fmt.Errorf("parse local address %q: %w", fields[1], err)
		}
		s := evidence.Socket{Proto: proto, Local: local}
		// For a listening socket, rx_queue is its accept queue's length
		// (sk_ack_backlog); tx_queue is 0, so the queue's limit isn't shown.
		if len(fields) > 4 {
			if _, rx, ok := strings.Cut(fields[4], ":"); ok {
				if n, err := strconv.ParseUint(rx, 16, 31); err == nil {
					s.Queued = int(n)
				}
			}
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseHexAddrPort decodes "0100007F:1F90" (127.0.0.1:8080). The kernel
// prints each 32-bit word of the address as a host-endian integer, so every
// word is converted back to network byte order with the machine's native
// endianness. IPv4-mapped IPv6 addresses are kept as they are: a socket bound
// to ::ffff:127.0.0.1 is still a tcp6 socket.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
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
	port, err := parseHexPort(portHex)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, port), nil
}

func parseHexPort(s string) (uint16, error) {
	if len(s) != 4 {
		return 0, fmt.Errorf("unexpected port %q", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}
