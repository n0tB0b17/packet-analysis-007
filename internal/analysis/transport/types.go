package transport

import (
	"sync"

	"github.com/google/gopacket"
)

type TransportStats struct {
	TCPPacketCount int
	UDPPacketCount int
	PortStats      map[int]int // port with packets
	TCPConnection  int
	Retransmission int
	StreamData     map[string]int               // key >> flowKey
	streams        map[string][]gopacket.Packet // key >> flowKey
}

type TransportAnalysis struct {
	stats TransportStats
	mu    sync.Mutex
}
