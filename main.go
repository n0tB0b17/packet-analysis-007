package main

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/n0tB0b17/tekcap/internal/analysis/network"
	"github.com/n0tB0b17/tekcap/internal/pcap"
)

func main() {
	pathToPCAP := "/home/baiman/Desktop/active-directory-scanner/pcap/packet-analysis/pcap_src/12_packet.pcap"

	reader := pcap.NewPCAPReader(pathToPCAP)
	analyzer := network.NewNetworkAnalyzer()

	packetChan := make(chan gopacket.Packet, 100)
	var wg sync.WaitGroup

	wg.Add(1)
	go reader.ReadPackets(packetChan, &wg)

	// running multiple analyzer
	numOfWorkers := 4
	for i := 1; i < numOfWorkers; i++ {
		wg.Add(1)
		go analyzer.ProcessPackets(packetChan, &wg)
	}
	wg.Wait()

	resp := analyzer.GetResult()
	fmt.Println("network layer analysis:")
	for key, value := range resp {
		fmt.Printf("%s: %v \n", key, value)
	}
}
