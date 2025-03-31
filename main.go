package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/n0tB0b17/tekcap/internal/analysis/application"
	"github.com/n0tB0b17/tekcap/internal/analysis/network"
	"github.com/n0tB0b17/tekcap/internal/analysis/transport"
	"github.com/n0tB0b17/tekcap/internal/pcap"
)

func main() {
	pathToPCAP := "/home/baiman/Desktop/active-directory-scanner/pcap/packet-analysis/pcap_src/300_tst_capture.pcap"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := pcap.NewPCAPReader(pathToPCAP)
	netAnalyzer := network.NewNetworkAnalyzer()
	tranAnalyzer := transport.NewTransportAnalyzer()
	appAnalyzer := application.NewApplicationLayerAnalyzer()

	packetChan := make(chan gopacket.Packet, 100)
	var wg sync.WaitGroup
	errorChan := make(chan error, 1)

	wg.Add(1)
	go func() {
		err := reader.ReadPackets(packetChan, &wg)
		if err != nil {
			errorChan <- err
		}
	}()

	numOfWorkers := 10
	for i := 1; i < numOfWorkers; i++ {
		wg.Add(3)
		go netAnalyzer.ProcessPackets(packetChan, &wg)
		go tranAnalyzer.ProcessPackets(packetChan, &wg)
		go appAnalyzer.ProcessPackets(packetChan, &wg)
	}

	go func() {
		select {
		case err := <-errorChan:
			fmt.Printf("unexpected error: %v", err)
			cancel()
		case <-ctx.Done():
		}
	}()
	wg.Wait()

	if ctx.Err() != nil {
		fmt.Println("error while closing context")
		return
	}

	fmt.Println("network layer analysis:")
	for key, value := range netAnalyzer.GetResult() {
		fmt.Printf("%s: %v \n", key, value)
	}

	fmt.Println("-----------------------------------------------------")
	fmt.Println("transport layer analysis:")
	for key, value := range tranAnalyzer.GetResult() {
		fmt.Printf("%s: %v \n", key, value)
	}

	fmt.Println("-----------------------------------------------------")
	fmt.Println("application layer analysis:")
	for key, value := range appAnalyzer.GetResult() {
		fmt.Printf("%s: %v \n", key, value)
	}
}
