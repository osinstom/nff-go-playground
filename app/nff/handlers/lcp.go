package handlers

import (
	"nff-go-playground/app/session"
	"github.com/intel-go/nff-go/packet"
	"fmt"
	"github.com/intel-go/nff-go/types"
	"errors"
)

func HandleLCP(current *packet.Packet, ctx *session.SessionContext) bool {
	ppp, err := current.GetPPP()
	if err != nil {
		return false
	}

	ctx.SetTransactionID(ppp.Identifier)
	return true
}

func PrepareLCPPacket(pkt *packet.Packet, ctx session.SessionContext, protocol uint16, code uint8) error {
	var totalLen uint8
	options := getOptionsFromAttributes(ctx, &totalLen)
	if !packet.InitEmptyPPPPacket(pkt, uint(totalLen)) {
		fmt.Println("Cannot initalizie PPPoES packet!")
		return errors.New("cannot initialize PPPoES packet")
	}

	InitPPPoES(pkt, ctx.GetSessionID(), packet.SwapBytesUint16(protocol),
		packet.SwapBytesUint16(uint16(types.PPPLen + totalLen + 2)))

	ppp := pkt.GetPPPNoOptions()
	ppp.Code = code
	ppp.Identifier = ctx.GetTransactionID()
	ppp.Length = packet.SwapBytesUint16(uint16(totalLen + types.PPPLen))
	ppp.Options = options

	pkt.SerializePPPOptions(ppp.Options)

	return nil
}

func getOptionsFromAttributes(ctx session.SessionContext, totalLen *uint8) []packet.PPPOption {
	var options []packet.PPPOption
	for key := range ctx.GetAttributes() {
		v, err := ctx.GetAttributeAsByteArray(key)
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
