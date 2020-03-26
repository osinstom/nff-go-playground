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
	"encoding/gob"
	"encoding/hex"
)

var pkt_cnt int = 0

var sessionManager SessionManager

type SessionCode struct {
	Protocol uint16
	Code     uint8
}

var codeSessionEventMap = map[SessionCode]SessionEvent {
	// PPPoE Discovery
	SessionCode{0, packet.PADI} 	: PADI,
	SessionCode{0, packet.PADO} 	: PADO,
	SessionCode{0, packet.PADR} 	: PADR,
	SessionCode{0, packet.PADS} 	: PADS,

	// Link Control Protocol
	SessionCode{packet.LCP, 0x01} 	: LCP_ConfReq,
	SessionCode{packet.LCP, 0x02} 	: LCP_ConfAck,

	// Challenge-Handshake Authentication Protocol
	SessionCode{packet.CHAP, 0x01} : CHAPChallenge,
	SessionCode{packet.CHAP, 0x02} : CHAPResponse,
	SessionCode{packet.CHAP, 0x03} : CHAPSuccess,
	SessionCode{packet.CHAP, 0x03} : CHAPFailure,
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

func preparePPPoEPacket(pkt *packet.Packet, ctx SessionContext, code uint8) error {
	var totalLen uint16
	tags := getTagsFromAttributes(ctx.attributes, &totalLen)
	if packet.InitEmptyPPPoEDPacket(pkt, uint(totalLen)) == false {
		fmt.Println("Cannot initalizie PPPoED packet!")
		return errors.New("cannot initialize PPPoED packet")
	}
	pppoe := pkt.GetPPPoEDNoTags()
	pppoe.VersionType = 0x11
	pppoe.SessionId = ctx.sessionId
	pppoe.Len = packet.SwapBytesUint16(totalLen)
	pppoe.Tags = tags
	pppoe.Code = code
	pkt.PacketBytesChange(types.EtherLen + types.PPPoELen, convertToBytes(pppoe.Tags))
	return nil
}

func preparePPPPacket(pkt *packet.Packet, ctx SessionContext, protocol uint16, code uint8) error {
	var totalLen uint8
	options := getOptionsFromAttributes(ctx, &totalLen)
	if !packet.InitEmptyPPPPacket(pkt, uint(totalLen)) {
		fmt.Println("Cannot initalizie PPPoES packet!")
		return errors.New("cannot initialize PPPoES packet")
	}
	pppoes := pkt.GetPPPoES()
	pppoes.VersionType = 0x11
	pppoes.SessionId = ctx.sessionId
	pppoes.Len = packet.SwapBytesUint16(uint16(types.PPPLen + totalLen + 2))
	pppoes.Code = 0x00
	pppoes.Protocol = packet.SwapBytesUint16(protocol)

	ppp := pkt.GetPPPNoOptions()
	ppp.Code = code
	ppp.Identifier = ctx.transactionId
	ppp.Length = packet.SwapBytesUint16(uint16(totalLen + types.PPPLen))
	ppp.Options = options

	pkt.SerializePPPOptions(ppp.Options)

	return nil
}

func getCHAPValueFromAttributes(attrs map[string]interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	val, ok := attrs["CHAP-Secret"]
	if !ok {
		return nil, errors.New("CHAP value has not been provided")
	}

	err := enc.Encode(val)
	if err != nil {
		return nil, errors.New("cannot convert CHAP value to byte array")
	}

	return buf.Bytes()[4:], nil
}
//
//func (ctx SessionContext) getAttributeAsByteArray(attr string) ([]byte, error) {
//	val, ok := ctx.attributes[attr]
//	if !ok {
//		return nil, fmt.Errorf("attribute '%v' has not been provided", attr)
//	}
//
//	var buf bytes.Buffer
//	enc := gob.NewEncoder(&buf)
//	fmt.Println("Encoding value: ", val)
//	err := enc.Encode(val)
//	if err != nil {
//		return nil, fmt.Errorf("cannot convert attribute '%v' to byte array", attr)
//	}
//	fmt.Println("Encoded value: ", hex.Dump(buf.Bytes()[4:]))
//	return buf.Bytes()[4:], nil
//}

func prepareCHAPPacket(pkt *packet.Packet, ctx SessionContext, protocol uint16, code uint8) error {
	value, err := ctx.getAttributeAsByteArray("CHAP-Secret")
	if err != nil {
		return err
	}
	name, err := ctx.getAttributeAsByteArray("CHAP-Name")
	if err != nil {
		return err
	}

	valueSize := uint8(len(value))

	totalLen := + 1 + len(name) + int(valueSize)
	if !packet.InitEmptyPPPPacket(pkt, uint(totalLen)) {
		fmt.Println("Cannot initalizie PPPoES packet!")
		return errors.New("cannot initialize PPPoES packet")
	}

	// FIXME: this is redundant
	pppoes := pkt.GetPPPoES()
	pppoes.VersionType = 0x11
	pppoes.SessionId = ctx.sessionId
	pppoes.Len = packet.SwapBytesUint16(uint16(types.PPPLen + totalLen + 2))
	pppoes.Code = 0x00
	pppoes.Protocol = packet.SwapBytesUint16(protocol)

	chap, err := pkt.GetCHAP()
	chap.Code = code
	chap.Identifier = ctx.transactionId
	chap.Length = packet.SwapBytesUint16(uint16(types.PPPLen + totalLen))

	payload := pkt.GetCHAPChallengeResponsePayload()
	payload.ValueSize = valueSize

	fmt.Println("Inserting Value, Name ", value, name)
	payload.Value = value
	payload.Name = name

	pkt.SerializeCHAPPayload(payload)

	fmt.Println("Constructed CHAP packet:\n", hex.Dump(pkt.GetRawPacketBytes()))

	return nil
}

func getOptionsFromAttributes(ctx SessionContext, totalLen *uint8) []packet.PPPOption {
	var options []packet.PPPOption
	for key := range ctx.attributes {
		v, err := ctx.getAttributeAsByteArray(key)
		if err != nil {
			fmt.Println(err)
			continue
		}
		options = append(options, packet.PPPOption{Type: packet.PPPOptionMap[key],
													Length: uint8(len(v)+2),
													Value: v})
		*totalLen += uint8(len(v)+2)
	}
	return options
}

func send(ctx SessionContext) {
	fmt.Println("Callback invoked!")
	pkt, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	protocol, code, err := fromSessionEventToSessionCode(ctx.event)

	var ok error
	if protocol == 0 {
		ok = preparePPPoEPacket(pkt, ctx, code)
	} else if protocol == packet.LCP {
		ok = preparePPPPacket(pkt, ctx, protocol, code)
	} else if protocol == packet.CHAP {
		ok = prepareCHAPPacket(pkt, ctx, protocol, code)
	} else {
		ok = errors.New("unknown Session Event")
	}

	if ok != nil {
		fmt.Println("Sending packet failed!")
		return
	}

	pkt.Ether.DAddr = ctx.subscriberMac
	pkt.Ether.SAddr = flow.GetPortMACAddress(0)

	fmt.Println("Sending packet:\n", hex.Dump(pkt.GetRawPacketBytes()))
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

func getTagsFromAttributes(attrs map[string]interface{}, totalLen *uint16) []packet.PPPoETag {
	var tags []packet.PPPoETag
	var buf bytes.Buffer
    enc := gob.NewEncoder(&buf)
	for key, val := range attrs {
		fmt.Println("Encoding value: ", val)
		err := enc.Encode(val)
		if err != nil {
			continue
		}
		v := buf.Bytes()[4:]
		fmt.Println("Encoded value: ", v)
		tags = append(tags, packet.PPPoETag{Type: packet.PPPoETagMapReversed[key],
										    Len: uint16(len(v)),
											Value: v})
		*totalLen += 4 + uint16(len(v))
		buf.Reset()
	}
	fmt.Println("Tags: ", tags)
	return tags
}

func dumper(currentPacket *packet.Packet, context flow.UserContext) {
	pkt_cnt++
	fmt.Println("Packet %v received..", pkt_cnt)
}

// This function should return pointer to the VXLAN payload.
func handleVXLAN(current *packet.Packet, context flow.UserContext) {
	current.ParseL3()
	ipv4 := current.GetIPv4()
	if ipv4 == nil {
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
		p, err := current.GetPPPoED()
		if err != nil {
			fmt.Println(err)
			return false
		}
		if p != nil {
			fmt.Println("Got PPPoED packet ", p.Code, packet.SwapBytesUint16(p.Len))
		}
		fmt.Println("Tags: ", p.Tags)
		sessionCtx.sessionId = packet.SwapBytesUint16(p.SessionId)
		sessionCtx.event = fromPPPCodeToSessionEvent(0, p.Code)
	} else if current.Ether.EtherType == types.SwapPPPoESNumber {
		p := current.GetPPPoES()
		sessionCtx.sessionId = packet.SwapBytesUint16(p.SessionId)
		ppp, err := current.GetPPP()
		if err != nil {
			return false
		}
		fmt.Println("PPP Options: ", ppp.Options)
		sessionCtx.transactionId = ppp.Identifier
		fmt.Println("PPPoES packet: ", packet.SwapBytesUint16(p.Protocol), ppp.Code)
		sessionCtx.event = fromPPPCodeToSessionEvent(packet.SwapBytesUint16(p.Protocol), ppp.Code)
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
	event, ok := codeSessionEventMap[SessionCode{Protocol: protocol, Code: code}]
	if ok {
		return event
	}
	return UNKNOWN
}

func fromSessionEventToSessionCode(evt SessionEvent) (uint16, uint8, error) {
	for key, val := range codeSessionEventMap {
		if val == evt {
			return key.Protocol, key.Code, nil
		}
	}
	return 0, 0, errors.New("PPP Code for SessionEvent doesn't exist")
}
