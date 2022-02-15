package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"strings"
	"time"
)

const (
	FilterSrc = iota
	FilterDst
	FilterAll
)

const CustomSeq = 10000

var (
	ErrNotFoundNic    = errors.New("not found nic")
	ErrNotFoundFilter = errors.New("not found filter rule")
	ErrNotValidPacket = errors.New("not valid packet")
	ErrSendSYNPacket  = errors.New("send syn packet error")
	ErrSendRSTPacket  = errors.New("send rst packet error")
	ErrDeadlineExit   = errors.New("intercept deadline exceeded")
)

type ToolFunc interface {
	Intercept() error
}

type Tool struct {
	noCopy

	/**
	 *  操作连接的四元组
	 */
	FourTuple

	// handle 连接句柄
	handle *pcap.Handle

	/**
	 * 拦截配置选项
	 */
	// nic 服务端的网卡 network interface card
	nic string
	// filter BPF过滤器规则
	filter []string
	// timeout 拦截时长
	timeout time.Duration
	// delay 延时拦截的时间
	delay time.Duration
	// retry 重传次数
	retry int
}

type FourTuple struct {
	// dstPort 目的端口
	dstPort layers.TCPPort
	// srcPort 源端口
	srcPort layers.TCPPort
	// dstIP 目的IP
	dstIP net.IP
	// srcIP 源IP
	srcIP net.IP
}

func (f FourTuple) String() string {
	return fmt.Sprintf("IP %s.%d > %s.%d: ", f.srcIP.String(), f.srcPort, f.dstIP.String(), f.dstPort)
}

func Build(nic string, options ...Option) (*Tool, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	selected := false
	for i := range devs {
		if devs[i].Name == nic {
			selected = true
		}
	}
	if !selected {
		return nil, ErrNotFoundNic
	}

	t := &Tool{
		nic:    nic,
		retry:  3,
		filter: []string{"tcp"},
	}
	for _, option := range options {
		option(t)
	}

	return t, nil
}

func (t *Tool) Intercept() error {
	if t.delay > 0 {
		log.Println("waiting delay time to intercept")
		<-time.After(t.delay)
	}

	err := t.filterPacket()
	defer t.handle.Close()
	if err != nil {
		return err
	}

	s := NewFourTuple(t.srcIP, t.dstIP, t.srcPort, t.dstPort)
	syn, err := FakeSYNPacket(s, CustomSeq)
	if err != nil {
		return err
	}

	packetSource := gopacket.NewPacketSource(
		t.handle,
		t.handle.LinkType(),
	)
	log.Printf("listen tcp on: %v", t.nic)
	packets := packetSource.Packets()

	log.Printf("[send] %sSYN, seq %d", s.String(), CustomSeq)
	if err = t.sendPacket(syn); err != nil {
		return ErrSendSYNPacket
	}

	if t.timeout > 0 {
		return t.captureWithTimeout(packets)
	}

	return t.captureLoop(packets)
}

func (t *Tool) captureLoop(packets chan gopacket.Packet) error {
	for packet := range packets {
		if err := t.process(packet); err != nil {
			return err
		}
	}

	return nil
}

func (t *Tool) captureWithTimeout(packets chan gopacket.Packet) error {
	timeout := time.After(t.timeout)
	for {
		select {
		case <-timeout:
			return ErrDeadlineExit
		case packet := <-packets:
			if err := t.process(packet); err != nil {
				return err
			}
		}
	}
}

func (t *Tool) process(packet gopacket.Packet) error {
	eth, ip, tcp, ok := Unpack(packet)
	if !ok {
		return ErrNotValidPacket
	}

	if tcp.SYN || tcp.FIN || tcp.RST {
		return nil
	}

	ack := tcp.Ack
	rcv := NewFourTuple(ip.DstIP, ip.SrcIP, tcp.DstPort, tcp.SrcPort)
	log.Printf("[recv] %sCHALLENGE-ACK, ack %d", rcv.String(), ack)

	ret := false
	for i := 0; i < t.retry; i++ {
		newSeq := ack + uint32(i)*uint32(tcp.Window)
		log.Printf("[send] %sRST, seq %d", rcv.String(), newSeq)
		rst, err := FakeRSTPacket(rcv, eth.DstMAC, eth.SrcMAC, newSeq)
		if err != nil {
			return err
		}
		if t.sendPacket(rst) == nil {
			ret = true
			break
		}
	}

	if !ret {
		return ErrSendRSTPacket
	}

	return nil
}

func (t *Tool) filterPacket() error {
	handle, err := pcap.OpenLive(t.nic, int32(65535), true, -1*time.Second)
	if err != nil {
		return err
	}

	if t.filter == nil {
		return ErrNotFoundFilter
	}
	err = handle.SetBPFFilter(strings.Join(t.filter, " and "))
	if err != nil {
		return err
	}

	t.handle = handle

	return nil
}

func (t *Tool) sendPacket(data []byte) error {
	return t.handle.WritePacketData(data)
}

func NewFourTuple(srcIP, dstIP net.IP, srcPort, dstPort layers.TCPPort) FourTuple {
	return FourTuple{
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
	}
}

func FakeRSTPacket(ft FourTuple, srcMac, dstMac net.HardwareAddr, seq uint32) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		SrcIP:    ft.srcIP,
		DstIP:    ft.dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: ft.srcPort,
		DstPort: ft.dstPort,
		Seq:     seq,
		RST:     true,
	}

	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		return nil, err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, options, &eth, &ip, &tcp); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func FakeSYNPacket(ft FourTuple, seq uint32) ([]byte, error) {
	ip := layers.IPv4{
		SrcIP:    ft.srcIP,
		DstIP:    ft.dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: ft.srcPort,
		DstPort: ft.dstPort,
		Seq:     seq,
		SYN:     true,
	}

	if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
		return nil, err
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, options, &ip, &tcp); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func Unpack(packet gopacket.Packet) (*layers.Ethernet, *layers.IPv4, *layers.TCP, bool) {
	// 链路层
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, nil, nil, false
	}
	eth := ethLayer.(*layers.Ethernet)

	// 网络层
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		log.Println("not ip layer")
		return nil, nil, nil, false
	}
	ip := ipv4Layer.(*layers.IPv4)

	// 传输层
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		log.Println("not tcp layer")
		return nil, nil, nil, false
	}
	tcp := tcpLayer.(*layers.TCP)

	return eth, ip, tcp, true
}

type noCopy struct{}

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
