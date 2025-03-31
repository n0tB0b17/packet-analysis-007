package pcap

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PCAPReader struct {
	filename string
}

func NewPCAPReader(filename string) *PCAPReader {
	return &PCAPReader{
		filename: filename,
	}
}

func (reader *PCAPReader) ReadPackets(packetChan chan<- gopacket.Packet, wg *sync.WaitGroup) error {
	defer wg.Done()

	handler, err := pcap.OpenOffline(reader.filename)
	if err != nil {
		fmt.Printf("error while opening pcap file: %v \n", err)
		close(packetChan)
		return err
	}
	defer handler.Close()

	linkType := handler.LinkType()
	fmt.Printf("Detected linktype: %d (%s)\n", linkType, linkType)

	if linkType == 20 || strings.Contains(linkType.String(), "UnknownLinkType") {
		close(packetChan)
		return fmt.Errorf("unsuported link-type: %s with integer value of: %d \n", linkType, linkType)
	}

	packetSRC := gopacket.NewPacketSource(handler, linkType)
	for packet := range packetSRC.Packets() {
		packetChan <- packet
	}
	close(packetChan)
	return nil
}
