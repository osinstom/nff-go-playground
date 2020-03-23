package main

import (
	"fmt"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"github.com/intel-go/nff-go/common"
)

var pkt_cnt int = 0

var sessionManager SessionManager

var f *flow.Flow

func main() {
	fmt.Println("App started.")
	sessionManager = SessionManager{SendReplyCallback: send}
	config := flow.Config{
		DisableScheduler: false,
		BurstSize: 1,
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
	flow.CheckFatal(flow.SetHandlerDrop(firstFlow, handlePPPoE, nil))
	flow.CheckFatal(flow.SetSenderOS(firstFlow, port))
	f = firstFlow
	flow.CheckFatal(flow.SystemStart())
}

func send() {
	fmt.Println("Callback invoked!")
	pkt, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	// FIXME: hardcoded addresses
	pkt.Ether.DAddr = types.MACAddress{0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x54}
	pkt.Ether.SAddr = types.MACAddress{0x00, 0x07, 0x0d, 0xaf, 0xf4, 0x55}
	pkt.Ether.EtherType = types.SwapPPPoEDNumber
	pkt.ParseL3()
	pppoe := pkt.GetPPPoEDNoTags()
	pppoe.SessionId = 0x0001
	pppoe.Code = 0x09


	pkt.SendPacketOS(flow.GetIODevice("eth0").(int))
	//socketID := flow.GetIODevice("eth0")
	//fmt.Println("Success? ", ok)
	//pkt.SendPacket(0)

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

func handlePPPoE(current *packet.Packet, ctx flow.UserContext) bool {
	current.ParseL3()
	var sessionCtx SessionContext
	if current.Ether.EtherType == types.SwapPPPoEDNumber {
		p := current.GetPPPoED()
		if p != nil {
			fmt.Println("Got PPPoED packet ", p.Code, p.Len)
		}
		fmt.Println(p.Tags)
		sessionCtx.sessionId = p.SessionId
		//sessionCtx.attributes = p.Tags
	} else if current.Ether.EtherType == types.SwapPPPoESNumber {
		current.GetPPPoES()
	} else {
		// Should drop
		return false
	}
	// handle session event in separate goroutine
	go sessionManager.HandleSessionEvent(sessionCtx)

	return false
}

//func handleSession(ctx SessionContext) {
//
//}

