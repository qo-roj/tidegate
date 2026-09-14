package main

import (
	"net"
	"testing"
)

func TestIsLoopback(t *testing.T) {
	cases := []struct {
		bind string
		want bool
	}{
		{"", true},
		{"localhost", true},
		{"loopback", true},
		{"127.0.0.1", true},
		{"127.0.0.2", true},        // whole 127/8 is loopback
		{"127.255.255.254", true},  // far end of 127/8
		{"::1", true},              // IPv6 loopback
		{"::ffff:127.0.0.1", true}, // IPv4-mapped IPv6 loopback
		{"127.0.0.1:8842", true},   // host:port tolerated
		{"0.0.0.0", false},         // all interfaces — NOT loopback
		{"192.168.1.50", false},    // LAN address
		{"::", false},              // IPv6 all-interfaces
		{"fe80::1", false},         // link-local, not loopback
		{"10.0.0.1:9000", false},   // host:port, non-loopback
	}
	for _, c := range cases {
		if got := isLoopback(c.bind); got != c.want {
			t.Errorf("isLoopback(%q) = %v, want %v", c.bind, got, c.want)
		}
	}
}

// Guard: net import stays used by isLoopback's parser path.
var _ = net.ParseIP
