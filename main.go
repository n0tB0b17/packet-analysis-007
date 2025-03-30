package main

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/n0tB0b17/tekcap/internal/analysis/network"
	"github.com/n0tB0b17/tekcap/internal/analysis/transport"
	"github.com/n0tB0b17/tekcap/internal/pcap"
)

func main() {
	pathToPCAP := "/home/baiman/Desktop/active-directory-scanner/pcap/packet-analysis/pcap_src/12_packet.pcap"

	reader := pcap.NewPCAPReader(pathToPCAP)
	Netanalyzer := network.NewNetworkAnalyzer()
	TranAnalyzer := transport.NewTransportAnalyzer()

	packetChan := make(chan gopacket.Packet, 100)
	var wg sync.WaitGroup

	wg.Add(1)
	go reader.ReadPackets(packetChan, &wg)

	numOfWorkers := 6
	for i := 1; i < numOfWorkers; i++ {
		wg.Add(2)
		go Netanalyzer.ProcessPackets(packetChan, &wg)
		go TranAnalyzer.ProcessPackets(packetChan, &wg)
	}
	wg.Wait()

	fmt.Println("network layer analysis:")
	for key, value := range Netanalyzer.GetResult() {
		fmt.Printf("%s: %v \n", key, value)
	}

	fmt.Println("-----------------------------------------------------")

	fmt.Println("transport layer analysis:")
	for key, value := range TranAnalyzer.GetResult() {
		fmt.Printf("%s: %v \n", key, value)
	}
}
