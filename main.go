package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// srcPortCounter hands out unique ephemeral source ports across concurrent
// scans. A time-based guess (UnixNano() % N) can collide between goroutines
// started in the same nanosecond window — see the callout below.
// Traslate in italian
// srcPortCounter distribuisce porte sorgente effimere uniche tra scansioni concorrenti.
// Una stima basata sul tempo (UnixNano() % N) può collidere tra goroutine
// avviate nella stessa finestra di nanosecondi — vedi il richiamo qui sotto.
var srcPortCounter uint32

func nextSrcPort() layers.TCPPort {
	n := atomic.AddUint32(&srcPortCounter, 1)
	return layers.TCPPort(40000 + n%20000)
}

type tcpSequencer struct {
	sequence uint32
}

func newTCPSequencer(seed uint32) *tcpSequencer {
	return &tcpSequencer{sequence: seed}
}

func (s *tcpSequencer) next() uint32 {
	return atomic.AddUint32(&s.sequence, 1) - 1
}

var sequences = newTCPSequencer(uint32(time.Now().UnixNano()))

func tcpReplyStatus(reply *layers.TCP, srcPort layers.TCPPort, sequence uint32) (string, bool) {
	if reply.DstPort != srcPort || !reply.ACK || reply.Ack != sequence+1 {
		return "", false
	}

	switch {
	case reply.SYN:
		return "open", true
	case reply.RST:
		return "closed", true
	default:
		return "", false
	}
}

func synScanPort(iface, srcIP, dstIP string, srcMAC, dstMAC net.HardwareAddr, dstPort layers.TCPPort) (string, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	srcPort := nextSrcPort()

	// Filter down to just the reply we care about before we ever read a packet.
	// dst host matters too — without it, a reply from a NAT gateway or a second
	// interface on the target would slip past src host and get missed entirely.
	filter := fmt.Sprintf("tcp and src host %s and dst host %s and src port %d and dst port %d", dstIP, srcIP, dstPort, srcPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		return "", err
	}
	sequence := sequences.next()

	// pcap.OpenLive captures at the link layer (Ethernet), so WritePacketData
	// needs a full frame — IP and TCP alone are not enough to put on the wire.
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     true,
		Window:  14600,
		Seq:     sequence,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return "", err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		return "", err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return "", err
	}

	// Read the reply on a goroutine and race it against a timeout — a filtered
	// port never sends a reply at all, so we can't just range over the packet
	// channel and check a deadline inside the loop body. That loop never runs
	// for a filtered port, and "range" on an unread channel blocks forever.
	resultCh := make(chan string, 1)
	go func() {
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range src.Packets() {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				reply, _ := tcpLayer.(*layers.TCP)
				if status, matched := tcpReplyStatus(reply, srcPort, sequence); matched {
					resultCh <- status
					return
				}
			}
		}
	}()

	select {
	case status := <-resultCh:
		return status, nil
	case <-time.After(3 * time.Second):
		return "filtered", nil
	}
}

func synScanRange(iface, srcIP, dstIP string, srcMAC, dstMAC net.HardwareAddr, startPort, endPort int, concurrency int) map[int]string {
	results := make(map[int]string)
	resultsCh := make(chan struct {
		port   int
		status string
	}, endPort-startPort+1)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			status, err := synScanPort(iface, srcIP, dstIP, srcMAC, dstMAC, layers.TCPPort(p))
			if err != nil {
				status = "error"
			}
			resultsCh <- struct {
				port   int
				status string
			}{p, status}
		}(port)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	for r := range resultsCh {
		results[r.port] = r.status
	}
	return results
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func newScanner(ip net.IP, router routing.Router) (*scanner, error) {
	s := &scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	// Figure out the route to the IP.
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	log.Printf("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	s.handle = handle

	return s, nil
}

// close cleans up the handle.
func (s *scanner) close() {
	s.handle.Close()
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (s *scanner) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("usage: %s <target-ip>", os.Args[0])
	}

	targetIP := net.ParseIP(os.Args[1])
	if targetIP == nil || targetIP.To4() == nil {
		log.Fatalf("invalid IPv4 target: %s", os.Args[1])
	}

	router, err := routing.New()
	if err != nil {
		log.Fatalf("error creating router: %v", err)
	}

	s, err := newScanner(targetIP, router)
	if err != nil {
		log.Fatalf("error creating scanner: %v", err)
	}
	defer s.close()

	dstMAC, err := s.getHwAddr()
	if err != nil {
		log.Fatalf("error resolving destination hardware address: %v", err)
	}

	results := synScanRange(
		s.iface.Name,
		s.src.String(),
		s.dst.String(),
		s.iface.HardwareAddr,
		dstMAC,
		1,
		65535,
		10,
	)
	for port := 1; port <= 65535; port++ {
		if results[port] == "open" {
			fmt.Printf("%d/tcp open\n", port)
		}
	}
}
