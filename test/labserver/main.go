// Command labserver is the stand-in service for the failure lab (test/lab).
// It plays a distroless app: a static binary on a FROM-scratch image, with no
// shell and no tools inside the container. Promoted from spikes/probe.
//
//	labserver serve [--delay 0s] ADDR...   listen on each TCP address and accept forever
//	labserver check HOST:PORT              exit 0 if a TCP connect succeeds (healthchecks)
//
// Any other mode exits with status 1, which the lab uses as a crashing service.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: labserver serve [--delay D] ADDR... | labserver check HOST:PORT")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "check":
		err = check(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "labserver:", err)
		os.Exit(1)
	}
}

// serve listens on every address it can and keeps going if one fails (for
// example when IPv6 is disabled in the container). --delay simulates a
// service that takes a while to start listening.
func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	delay := fs.Duration("delay", 0, "wait this long before listening")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if *delay > 0 {
		select {
		case <-time.After(*delay):
		case <-ctx.Done():
			return nil
		}
	}
	for _, a := range fs.Args() {
		ap, err := netip.ParseAddrPort(a)
		if err != nil {
			return err
		}
		network := "tcp4" // like most apps binding 0.0.0.0: IPv4 only
		if ap.Addr().Is6() {
			network = "tcp6"
		}
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "labserver: listen %s: %v\n", a, err)
			continue
		}
		go accept(ln)
	}
	<-ctx.Done()
	return nil
}

func accept(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}
}

// check exits 0 when HOST:PORT accepts a TCP connection within a second.
func check(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: labserver check HOST:PORT")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", args[0])
	if err != nil {
		return err
	}
	return c.Close()
}
