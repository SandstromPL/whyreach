package procnet

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

const tcp4Table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 65534        0 123456 1 0000000000000000 100 0 0 10 0
   1: 00000000:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 123457 1 0000000000000000 100 0 0 10 0
   2: 0400A8C0:C350 0500A8C0:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 123458 1 0000000000000000 20 4 30 10 -1
`

const tcp6Table = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:2383 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223456 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223457 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223458 1 0000000000000000 100 0 0 10 0
`

func TestParse(t *testing.T) {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("fixtures were captured on a little-endian machine")
	}
	tests := []struct {
		name  string
		table string
		proto string
		want  []Socket
	}{
		{
			name: "tcp4", table: tcp4Table, proto: "tcp",
			want: []Socket{
				{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:8080"), State: "LISTEN", Inode: 123456},
				{Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:9090"), State: "LISTEN", Inode: 123457},
				{Proto: "tcp", Local: netip.MustParseAddrPort("192.168.0.4:50000"), State: "ESTABLISHED", Inode: 123458},
			},
		},
		{
			name: "tcp6", table: tcp6Table, proto: "tcp6",
			want: []Socket{
				{Proto: "tcp6", Local: netip.MustParseAddrPort("[::]:9091"), State: "LISTEN", Inode: 223456},
				{Proto: "tcp6", Local: netip.MustParseAddrPort("[::1]:8081"), State: "LISTEN", Inode: 223457},
				{Proto: "tcp6", Local: netip.MustParseAddrPort("[::ffff:127.0.0.1]:8082"), State: "LISTEN", Inode: 223458},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tt.table), tt.proto)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d sockets, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("row %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	table := "header\n   0: ZZZZ:1F90 00000000:0000 0A 0 0 0 0 0 1\n"
	if _, err := Parse(strings.NewReader(table), "tcp"); err == nil {
		t.Fatal("expected an error for a non-hex address")
	}
}
