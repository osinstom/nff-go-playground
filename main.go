package main

import (
	"fmt"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

var pkt_cnt int = 0

func main() {
	fmt.Println("App started.")
	config := flow.Config{
		DisableScheduler: false,
		BurstSize: 4,
	}
	err := flow.SystemInit(&config)
	if err != nil {
		fmt.Printf("Some error occured: %v\n", err)
		return
	}
	//inQueue := 1
	port := "eth0" // TODO: hardcoded
	firstFlow, err := flow.SetReceiverOS(port)
	//firstFlow, err := flow.SetReceiverXDP(port, inQueue)
	flow.CheckFatal(flow.SetHandler(firstFlow, dumper, nil))
	flow.CheckFatal(flow.SetHandler(firstFlow, handleVXLAN, nil))
	flow.CheckFatal(flow.SetHandler(firstFlow, handlePPPoE, nil))
	flow.CheckFatal(flow.SetSenderOS(firstFlow, port))
	flow.CheckFatal(flow.SystemStart())
}

func dumper(currentPacket *packet.Packet, context flow.UserContext) {
	pkt_cnt++
	fmt.Println("Packet %v received..", pkt_cnt)
	fmt.Printf("%v", currentPacket.Ether)
}

// This function should return pointer to the VXLAN payload.
func handleVXLAN(current *packet.Packet, context flow.UserContext) {
	current.ParseL3()
	ipv4 := current.GetIPv4()
	if ipv4 == nil {
		fmt.Println("Non IP packet received..")
		return
	}
	current.ParseL4ForIPv4()
	udp := current.GetUDPForIPv4()

	if udp == nil || udp.DstPort != 4789 {
		// reject un-tunneled packet
		println("UDP not present or it is not VXLAN packet")
		return
	}
}

func handlePPPoE(current *packet.Packet, ctx flow.UserContext) {
	current.ParseL3()


	if current.Ether.EtherType == types.SwapPPPoEDNumber {
		p := current.GetPPPoED()
		if p != nil {
			fmt.Println("Got PPPoED packet ", p)
		}
	} else if current.Ether.EtherType == types.SwapPPPoESNumber {
		current.GetPPPoES()
	} else {
		// Should drop
	}



}

