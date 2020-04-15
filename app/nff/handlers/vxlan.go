package handlers

import (
	"fmt"
	"github.com/intel-go/nff-go/types"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/flow"
	"nff-go-playground/app/cups"
)

// This function should return pointer to the VXLAN payload.
// In case of BNG-CP it should be a pointer to the first byte of BNG Service Header.
func HandleVXLAN(current *packet.Packet, context flow.UserContext) {
	current.ParseL3()
	ipv4 := current.GetIPv4()
	if ipv4 == nil {
		return
	}
	current.ParseL4ForIPv4()
	udp := current.GetUDPForIPv4()

	if udp == nil || udp.DstPort != packet.SwapBytesUint16(4789) {
		// reject un-tunneled packet
		fmt.Println("UDP not present or it is not VXLAN packet")
		return
	}

	newBngDp := cups.BngDp{IPAddr:ipv4.SrcAddr, MACAddr:current.Ether.SAddr}

	if bngId, err := cups.BngDpMap[newBngDp]; !err {
		id := uint8(len(cups.BngDpMap))  // set ID of BNG equals to current length
		cups.BngDpMap[newBngDp] = id
		cups.BngDpMapReversed[id] = newBngDp
	} else {
		// FIXME: really temporary solution
		cups.BngId = bngId
	}

	// Remove VXLAN header
	current.DecapsulateHead(0, types.EtherLen+types.IPv4MinLen+types.UDPLen+types.VXLANLen)
}