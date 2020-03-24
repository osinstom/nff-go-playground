package main

import (
	"fmt"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"github.com/intel-go/nff-go/common"
	"errors"
	"bytes"
	"encoding/binary"
)

var pkt_cnt int = 0

var sessionManager SessionManager

var codeSessionEventMap = map[uint32]SessionEvent {
	packet.PADI 			: PADI,
	packet.PADO 			: PADO,
	packet.PADR 			: PADR,
	packet.PADS 			: PADS,
	(packet.LCP<<8)|0x01 	: LCP_ConfReq,
}

func main() {
	fmt.Println("App started.")
	sessionManager = SessionManager{SendReplyCallback: send}

	config := flow.Config{
		NeedKNI:  true,
		DPDKArgs: []string{"--no-pci", "--vdev=eth_af_packet0,iface=" + "eth0"},
		DisableScheduler: false,
		BurstSize: 1,
	}
	err := flow.SystemInit(&config)
	if err != nil {
		fmt.Printf("Some error occured: %v\n", err)
		return
	}
	//inQueue := 1

	firstFlow, err := flow.SetReceiver(0)
	//firstFlow, err := flow.SetReceiverXDP(port, inQueue)
	flow.CheckFatal(flow.SetHandler(firstFlow, dumper, nil))
	flow.CheckFatal(flow.SetHandler(firstFlow, handleVXLAN, nil))
	flow.CheckFatal(flow.SetHandlerDrop(firstFlow, handlePPPoE, nil))
	flow.CheckFatal(flow.SetSender(firstFlow, 0))
	flow.CheckFatal(flow.SystemStart())
}

func send(ctx SessionContext) {
	fmt.Println("Callback invoked!")
	pkt, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	var totalLen uint16
	tags := getTagsFromAttributes(ctx.attributes, &totalLen)

	if packet.InitEmptyPPPoEDPacket(pkt, uint(totalLen)) == false {
		fmt.Println("Cannot initalizie PPPoED packet!")
		return
	}

	pkt.Ether.DAddr = ctx.subscriberMac
	pkt.Ether.SAddr = flow.GetPortMACAddress(0)

	pppoe := pkt.GetPPPoEDNoTags()
	pppoe.VersionType = 0x11
	pppoe.SessionId = ctx.sessionId
	pppoe.Len = packet.SwapBytesUint16(totalLen)
	pppoe.Tags = tags

	code, err := fromSessionEventToPPPoECode(ctx.event)
	if err != nil {
		common.LogDebug(common.Debug, "Sending reply failed: ", err)
		return
	}
	pppoe.Code = code

	pkt.PacketBytesChange(types.EtherLen + types.PPPoELen, convertToBytes(pppoe.Tags))

	fmt.Println("Sending packet: ", pkt.GetRawPacketBytes())
	pkt.SendPacket(0)
}

func convertToBytes(tags []packet.PPPoETag) []byte {
	var bin_buf bytes.Buffer
	for _, tag := range tags {
		binary.Write(&bin_buf, binary.BigEndian, tag.Type)
		binary.Write(&bin_buf, binary.BigEndian, tag.Len)
		bin_buf.Write(tag.Value)
	}
	return bin_buf.Bytes()
}

func getTagsFromAttributes(attrs map[string]string, totalLen *uint16) []packet.PPPoETag {
	var tags []packet.PPPoETag
	for key, val := range attrs {
		tags = append(tags, packet.PPPoETag{Type: packet.PPPoETagMapReversed[key],
										    Len: uint16(len([]byte(val))),
											Value: []byte(val)})
		*totalLen += 4 + uint16(len([]byte(val)))
	}
	return tags
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
			fmt.Println("Got PPPoED packet ", p.Code, packet.SwapBytesUint16(p.Len))
		}
		fmt.Println("Tags: ", p.Tags)
		sessionCtx.sessionId = p.SessionId
		sessionCtx.event = fromPPPCodeToSessionEvent(0, p.Code)
	} else if current.Ether.EtherType == types.SwapPPPoESNumber {
		p := current.GetPPPoES()
		sessionCtx.sessionId = p.SessionId
		fmt.Println("PPPoES packet: ", packet.SwapBytesUint16(p.Protocol), p.Code)




		sessionCtx.event = fromPPPCodeToSessionEvent(packet.SwapBytesUint16(p.Protocol), p.Code)
	} else {
		// Should drop
		return false
	}
	sessionCtx.subscriberMac = current.Ether.SAddr
	// handle session event in separate goroutine
	go sessionManager.HandleSessionEvent(sessionCtx)

	return false
}

func fromPPPCodeToSessionEvent(protocol uint16, code uint8) SessionEvent {
	event, ok := codeSessionEventMap[uint32(protocol)<<8|uint32(code)]
	if ok {
		return event
	}
	return UNKNOWN
}

func fromSessionEventToPPPoECode(evt SessionEvent) (uint8, error) {
	for key, val := range codeSessionEventMap {
		if val == evt {
			return uint8(key), nil
		}
	}
	return 0, errors.New("PPP Code for SessionEvent doesn't exist")
}

//func handleSession(ctx SessionContext) {
//
//}

