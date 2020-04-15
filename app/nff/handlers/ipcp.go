package handlers

import (
	"nff-go-playground/app/session"
	"github.com/intel-go/nff-go/packet"
	"net"
	"github.com/intel-go/nff-go/types"
	"errors"
	"fmt"
)

func HandleIPCP(pkt *packet.IPCPHdr, ctx *session.SessionContext) {
	fmt.Println(pkt.Options)
	//fmt.Println("IPCP packet received: ", p.Identifier, p.Code, p.Length)
	for _, opt := range pkt.Options {
		if opt.Type == packet.IPCP_IPAddressOption {
			ctx.SetAttribute("IP-Address", opt.Address)
		}
	}

}

func PrepareIPCPPacket(pkt *packet.Packet, ctx session.SessionContext, protocol uint16, code uint8) error {
	if !packet.InitEmptyPPPPacket(pkt, 0) {
		return errors.New("cannot initialize IPCP packet")
	}

	pppoes := InitPPPoES(pkt, ctx.GetSessionID(), packet.SwapBytesUint16(protocol), 0)

	ipcp := pkt.GetIPCPNoOptions()
	ipcp.Code = code
	ipcp.Identifier = ctx.GetTransactionID()

	var optionsLen uint16
	for attr, value := range ctx.GetAttributes() {
		switch attr {
		case "IP-Address": {
			addr := net.ParseIP(value.(string)).To4()
			ipcp.AppendIPAddressOption(types.BytesToIPv4(addr[3], addr[2], addr[1], addr[0]))
			optionsLen += 6  // each IPCP options has length equal to 6
		}
		}
	}

	// Update length
	ipcp.Length = packet.SwapBytesUint16(uint16(types.PPPLen + optionsLen))
	pppoes.Len = packet.SwapBytesUint16(uint16(types.PPPLen + optionsLen + 2))

	// increase MBuf, TODO: should be moved before allocating payload
	pkt.EncapsulateTail(pkt.GetPacketLen(), uint(optionsLen))
	pkt.SerializeIPCPOptions(ipcp.Options)

	return nil
}

