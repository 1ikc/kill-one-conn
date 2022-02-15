package main

import (
	"flag"
	"log"
	"time"
)

var nic = flag.String("nic", "", "network interface card")
var retry = flag.Int("retry", 3, "retry send num")
var srcIP = flag.String("src_ip", "", "src ip")
var dstIP = flag.String("dst_ip", "", "dst ip")
var srcPort = flag.Int("src_port", 0, "src port")
var dstPort = flag.Int("dst_port", 0, "dst port")
var timeout = flag.Int("timeout", 0, "timeout")
var delay = flag.Int("delay", 0, "delay")

func main() {
	flag.Parse()

	options := initOption()
	if len(options) == 0 {
		log.Fatal("at least 1 param")
	}

	t, err := Build(
		*nic,
		options...,
	)
	if err != nil {
		log.Fatalf("build error :%v", err)
	}
	err = t.Intercept()
	if err != nil {
		log.Fatalf("intercept error: %v", err)
	}

	log.Println("end")
}

func initOption() []Option {
	options := []Option(nil)

	if *retry > 0 {
		options = append(options, Retry(*retry))
	}
	if *timeout > 0 {
		options = append(options, Timeout(time.Duration(*timeout)*time.Millisecond))
	}
	if *delay > 0 {
		options = append(options, Delay(time.Duration(*delay)*time.Millisecond))
	}

	if len(*srcIP) > 0 {
		options = append(options, IP(*srcIP, FilterSrc))
	}
	if len(*dstIP) > 0 {
		options = append(options, IP(*dstIP, FilterDst))
	}

	if *srcPort > 0 && *srcPort <= 65535 {
		options = append(options, Port(*srcPort, FilterSrc))
	}
	if *dstPort > 0 && *dstPort <= 65535 {
		options = append(options, Port(*dstPort, FilterDst))
	}

	return options
}
