// Command dnscount is a throwaway DNS server for the Q13–Q15 experiments
// (spikes/q13q15.sh, results in docs/research/q13-q15-experiments.md).
//
//	dnscount [ADDR]   serve DNS on ADDR (default :53) over UDP and TCP
//
// It answers every A query with 192.0.2.1 (TEST-NET-1) and every other type
// with an empty answer, and prints one line per question to stdout, so the
// experiment can count which queries reached it. A name containing the label
// "ttl60" is answered with a TTL of 60 seconds; every other name gets 0.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func main() {
	addr := ":53"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	dns.HandleFunc(".", answer)
	errc := make(chan error, 2)
	for _, network := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: addr, Net: network}
		go func() { errc <- srv.ListenAndServe() }()
	}
	fmt.Fprintln(os.Stderr, "dnscount:", <-errc)
	os.Exit(1)
}

func answer(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	for _, q := range r.Question {
		name := strings.ToLower(q.Name)
		fmt.Fprintf(os.Stdout, "%s %s %s %s\n", time.Now().UTC().Format(time.RFC3339Nano),
			w.RemoteAddr().Network(), dns.TypeToString[q.Qtype], name)
		var ttl uint32
		if strings.Contains("."+name, ".ttl60.") {
			ttl = 60
		}
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.IPv4(192, 0, 2, 1),
			})
		}
	}
	if err := w.WriteMsg(m); err != nil {
		fmt.Fprintln(os.Stderr, "dnscount: reply:", err)
	}
}
