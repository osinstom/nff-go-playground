package handlers

import (
	"nff-go-playground/app/session"
	"github.com/intel-go/nff-go/packet"
	"fmt"
	"github.com/intel-go/nff-go/types"
	"errors"
)

func HandleCHAP(current *packet.Packet, baseHdr *packet.PPPHdr, ctx *session.SessionContext) {
	if baseHdr.Code == packet.CHAPChallengeCode || baseHdr.Code == packet.CHAPResponseCode {
		payload := current.GetCHAPChallengeResponsePayload(packet.SwapBytesUint16(baseHdr.Length))
		ctx.SetAttribute("CHAP-Secret", string(payload.Value))
		ctx.SetAttribute("CHAP-Name", string(payload.Name))
	}
}


// This function prepares CHAP packet to be sent out.
// FIXME: The function contains unsafe operation: segments of memory are modified (e.g. GetCHAPChallangeResponsePayload)
// FIXME: before packet MBuf is  // increased (pkt.EncapsulateTail()). We should allocate enough memory in the first line
// FIXME: of function (InitEmptyPPPPacket()). To do that we need SessionContext to calculate size of its attributes.
func PrepareCHAPPacket(pkt *packet.Packet, ctx session.SessionContext, protocol uint16, code uint8) error {
	if !packet.InitEmptyPPPPacket(pkt, 0) {
		fmt.Println("Cannot initalizie PPPoES packet!")
		return errors.New("cannot initialize PPPoES packet")
	}

	pppoes := InitPPPoES(pkt, ctx.GetSessionID(), packet.SwapBytesUint16(protocol), 0)

	chap := pkt.GetCHAP()
	chap.Code = code
	chap.Identifier = ctx.GetTransactionID()

	var payload interface{}
	var payloadSize int
	if code == packet.CHAPChallengeCode || code == packet.CHAPResponseCode {
		payload = pkt.GetCHAPChallengeResponsePayload(0)
		p := payload.(*packet.CHAPChallengeResponsePayload)
		prepareCHAPChallengeOrResponse(p, ctx)
		payloadSize = 1 + int(p.ValueSize) + len(p.Name)
	} else if code == packet.CHAPSuccessCode || code == packet.CHAPFailureCode {
		payload = pkt.GetCHAPSuccessFailurePayload()
		p := payload.(*packet.CHAPSuccessFailurePayload)
		prepareCHAPSuccessOrFailurePayload(p, ctx)
		payloadSize = len(p.Message)
	} else {
		return nil
	}

	// Update length
	chap.Length = packet.SwapBytesUint16(uint16(types.PPPLen + payloadSize))
	pppoes.Len = packet.SwapBytesUint16(uint16(types.PPPLen + payloadSize + 2))

	// increase MBuf, TODO: should be moved before allocating payload
	pkt.EncapsulateTail(pkt.GetPacketLen(), uint(payloadSize))
	pkt.SerializeCHAPPayload(payload)
	return nil
}

func prepareCHAPChallengeOrResponse(payload *packet.CHAPChallengeResponsePayload, ctx session.SessionContext) (error) {
	value, err := ctx.GetAttributeAsByteArray("CHAP-Secret")
	if err != nil {
		return err
	}
	name, err := ctx.GetAttributeAsByteArray("CHAP-Name")
	if err != nil {
		return err
	}

	valueSize := uint8(len(value))
	payload.ValueSize = valueSize
	payload.Value = value
	payload.Name = name

	return nil
}

func prepareCHAPSuccessOrFailurePayload(payload *packet.CHAPSuccessFailurePayload,
										ctx session.SessionContext) (error) {
	message, err := ctx.GetAttributeAsByteArray("CHAP-Message")
	if err != nil {
		// don't return error, initialize empty message
		message = []byte{}
	}
	payload.Message = message
	return nil
}
