package main

import (
	"math"
	"testing"

	"github.com/google/gopacket/layers"
)

func TestTCPSequencer(t *testing.T) {
	sequencer := newTCPSequencer(100)

	if got := sequencer.next(); got != 100 {
		t.Fatalf("first sequence = %d, want 100", got)
	}
	if got := sequencer.next(); got != 101 {
		t.Fatalf("second sequence = %d, want 101", got)
	}
}

func TestTCPSequencerWraps(t *testing.T) {
	sequencer := newTCPSequencer(math.MaxUint32)

	if got := sequencer.next(); got != math.MaxUint32 {
		t.Fatalf("first sequence = %d, want %d", got, uint32(math.MaxUint32))
	}
	if got := sequencer.next(); got != 0 {
		t.Fatalf("wrapped sequence = %d, want 0", got)
	}
}

func TestTCPReplyStatus(t *testing.T) {
	srcPort := layers.TCPPort(40001)
	sequence := uint32(12345)

	tests := []struct {
		name    string
		reply   layers.TCP
		status  string
		matched bool
	}{
		{
			name:    "matching SYN-ACK is open",
			reply:   layers.TCP{DstPort: srcPort, SYN: true, ACK: true, Ack: sequence + 1},
			status:  "open",
			matched: true,
		},
		{
			name:    "matching RST-ACK is closed",
			reply:   layers.TCP{DstPort: srcPort, RST: true, ACK: true, Ack: sequence + 1},
			status:  "closed",
			matched: true,
		},
		{
			name:  "wrong acknowledgment is ignored",
			reply: layers.TCP{DstPort: srcPort, SYN: true, ACK: true, Ack: sequence},
		},
		{
			name:  "wrong destination port is ignored",
			reply: layers.TCP{DstPort: srcPort + 1, SYN: true, ACK: true, Ack: sequence + 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, matched := tcpReplyStatus(&test.reply, srcPort, sequence)
			if status != test.status || matched != test.matched {
				t.Fatalf("tcpReplyStatus() = (%q, %t), want (%q, %t)", status, matched, test.status, test.matched)
			}
		})
	}
}