package main

import (
	"github.com/google/gopacket/layers"
	"net"
	"strconv"
	"time"
)

type Option func(t *Tool)

func Timeout(timeout time.Duration) Option {
	return func(t *Tool) {
		t.timeout = timeout
	}
}

func Delay(timeout time.Duration) Option {
	return func(t *Tool) {
		t.delay = timeout
	}
}

func Retry(num int) Option {
	return func(t *Tool) {
		if num <= 0 {
			return
		}
		t.retry = num
	}
}

func Port(port int, filterType int) Option {
	return func(t *Tool) {
		port2 := layers.TCPPort(port)
		switch filterType {
		case FilterSrc:
			if t.srcPort != 0 {
				return
			}
			t.srcPort = port2
			t.filter = append(t.filter, "src port "+strconv.Itoa(port))
		case FilterDst:
			if t.dstPort != 0 {
				return
			}
			t.dstPort = port2
			t.filter = append(t.filter, "dst port "+strconv.Itoa(port))
		case FilterAll:
			if t.srcPort != 0 || t.dstPort != 0 {
				return
			}
			t.srcPort = port2
			t.dstPort = port2
			t.filter = append(t.filter, "port "+strconv.Itoa(port))
		}
	}
}

func IP(ip string, filterType int) Option {
	return func(t *Tool) {
		ip2 := net.ParseIP(ip)
		switch filterType {
		case FilterSrc:
			if t.srcIP != nil {
				return
			}
			t.srcIP = ip2
			t.filter = append(t.filter, "src host "+ip)
		case FilterDst:
			if t.dstIP != nil {
				return
			}
			t.dstIP = ip2
			t.filter = append(t.filter, "dst host "+ip)
		case FilterAll:
			if t.srcIP != nil || t.dstIP != nil {
				return
			}
			t.srcIP = ip2
			t.dstIP = ip2
			t.filter = append(t.filter, "host "+ip)
		}
	}
}
