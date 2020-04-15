package handlers

import (
	"nff-go-playground/app/session"
	"fmt"
	"github.com/intel-go/nff-go/packet"
	"encoding/hex"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/common"
	"errors"
	"github.com/intel-go/nff-go/types"
	"nff-go-playground/app/cups"
	"nff-go-playground/app/bngcp"
)

func Send(ctx session.SessionContext) {
	pkt, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	protocol, code, err := FromSessionEventToSessionCode(ctx.GetEvent())
	if err != nil {
		fmt.Println(err)
		return
	}

	if protocol == 0 {
		err = PreparePPPoEDPacket(pkt, ctx, code)
	} else if protocol == packet.LCP {
		err = PrepareLCPPacket(pkt, ctx, protocol, code)
	} else if protocol == packet.CHAP {
		err = PrepareCHAPPacket(pkt, ctx, protocol, code)
	} else if protocol == packet.IPCP {
		err = PrepareIPCPPacket(pkt, ctx, protocol, code)
	} else {
		err = errors.New("unknown Session Event")
	}

	if err != nil {
		fmt.Printf("Sending packet failed (%v)!\n", err)
		return
	}

	pkt.Ether.DAddr = ctx.GetSubscriberMAC()
	pkt.Ether.SAddr = flow.GetPortMACAddress(0)

	if ctx.GetVLANID() != 0 {
		pkt.AddVLANTag(ctx.GetVLANID())
	}
	fmt.Println(hex.Dump(pkt.GetRawPacketBytes()))
	fmt.Println("Packet length: ", pkt.GetPacketLen())
	if ok := pkt.EncapsulateIPv4VXLANGPEoUDP(0, packet.NextProtocolEthernet); !ok {
		fmt.Println("Error while encapsulating into VXLAN GPE")
		return
	}
	fmt.Println(hex.Dump(pkt.GetRawPacketBytes()))
	fmt.Println("Packet length: ", pkt.GetPacketLen())
	length := pkt.GetPacketLen()

	pkt.Ether.SAddr = bngcp.GetBNGControlPlaneInstance().GetMACAddress()
	pkt.Ether.DAddr = cups.BngDpMapReversed[ctx.GetBNGDpId()].MACAddr
	pkt.Ether.EtherType = types.SwapIPV4Number
	pkt.ParseL3()
	pktIP := (*packet.IPv4Hdr)(pkt.L3)
	// construct iphdr
	pktIP.VersionIhl = 0x45
	pktIP.TypeOfService = 0
	pktIP.PacketID = 0x1513
	pktIP.FragmentOffset = 0
	pktIP.TimeToLive = 64
	pktIP.TotalLength = packet.SwapBytesUint16(uint16(length - types.EtherLen))
	pktIP.DstAddr = cups.BngDpMapReversed[ctx.GetBNGDpId()].IPAddr
	pktIP.SrcAddr = bngcp.GetBNGControlPlaneInstance().GetIPAddress()
	pktIP.NextProtoID = types.UDPNumber
	pktIP.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pktIP))

	pkt.ParseL4ForIPv4()
	udp := pkt.GetUDPNoCheck()
	udp.SrcPort = packet.SwapBytesUint16(packet.UDPPortVXLAN_GPE)
	udp.DstPort = packet.SwapBytesUint16(packet.UDPPortVXLAN_GPE)
	udp.DgramLen = packet.SwapBytesUint16(uint16(length - types.EtherLen - types.IPv4MinLen))
	udp.DgramCksum = 0

	fmt.Println("Sending packet:\n", hex.Dump(pkt.GetRawPacketBytes()))
	ok := pkt.SendPacket(0)
	if !ok {
		fmt.Println("Sending packet failed.")
	}
}
