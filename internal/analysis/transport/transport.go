package transport

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func NewTransportAnalyzer() *TransportAnalysis {
	return &TransportAnalysis{
		stats: TransportStats{
			PortStats:  make(map[int]int),
			StreamData: make(map[string]int),
			streams:    make(map[string][]gopacket.Packet),
		},
	}
}

func (ta *TransportAnalysis) Analyze(packet gopacket.Packet) error {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		ta.mu.Lock()
		defer ta.mu.Unlock()

		ta.stats.TCPPacketCount++
		ta.stats.PortStats[int(tcp.SrcPort)]++
		ta.stats.PortStats[int(tcp.DstPort)]++

		//tracking tcp connection with flowKey
		flowKey := fmt.Sprintf("%s:%d-%s:%d",
			packet.NetworkLayer().NetworkFlow().Src().String(),
			tcp.SrcPort,
			packet.NetworkLayer().NetworkFlow().Dst().String(),
			tcp.DstPort,
		)

		if tcp.SYN && !tcp.ACK {
			ta.stats.streams[flowKey] = append(ta.stats.streams[flowKey], packet)
		} else if tcp.SYN && tcp.ACK {
			if segment, exists := ta.stats.streams[flowKey]; exists && len(segment) > 0 {
				ta.stats.TCPConnection++
			}
		} else if tcp.FIN || tcp.RST {
			ta.handleStreamCompletion(flowKey)
		}

		ta.handleTCPStream(flowKey, packet, tcp)
		return nil
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		ta.mu.Lock()
		defer ta.mu.Unlock()

		ta.stats.UDPPacketCount++
		ta.stats.PortStats[int(udp.SrcPort)]++
		ta.stats.PortStats[int(udp.DstPort)]++

		flowKey := fmt.Sprintf("%s:%d-%s:%d",
			packet.NetworkLayer().NetworkFlow().Src().String(),
			udp.SrcPort,
			packet.NetworkLayer().NetworkFlow().Dst().String(),
			udp.DstPort,
		)

		ta.stats.StreamData[flowKey] += len(udp.Payload)
	}

	return nil
}

func (ta *TransportAnalysis) GetResult() map[string]interface{} {
	return map[string]interface{}{
		"TCPPacketCount": ta.stats.TCPConnection,
		"UDPPacketCount": ta.stats.UDPPacketCount,
		"PortStats":      ta.stats.PortStats,
		"TCPConnection":  ta.stats.TCPConnection,
		"Retransmission": ta.stats.Retransmission,
		"StreamData":     ta.stats.StreamData,
	}
}

func (ta *TransportAnalysis) handleTCPStream(flowKey string, packet gopacket.Packet, tcp *layers.TCP) {
	segments := ta.stats.streams[flowKey]
	for _, segment := range segments {
		prevTCP := segment.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if tcp.Seq == prevTCP.Seq && len(tcp.Payload) > 0 {
			ta.stats.Retransmission++
			return
		}
	}

	if len(tcp.Payload) > 0 {
		ta.stats.streams[flowKey] = append(ta.stats.streams[flowKey], packet)
		ta.stats.StreamData[flowKey] += len(tcp.Payload)
	}
}

func (ta *TransportAnalysis) handleStreamCompletion(flowKey string) {
	if segments, exists := ta.stats.streams[flowKey]; exists && len(segments) > 0 {
		fmt.Printf("Completed TCP stream %s with %d bytes \n", flowKey, ta.stats.StreamData[flowKey])
		delete(ta.stats.streams, flowKey)
	}
}

func (ta *TransportAnalysis) ProcessPackets(packetChan <-chan gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()
	for packet := range packetChan {
		if err := ta.Analyze(packet); err != nil {
			fmt.Println("Error while processing packets")
		}
	}
}
