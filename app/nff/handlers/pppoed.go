package handlers

import (
	"nff-go-playground/app/session"
	"fmt"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"errors"
	"encoding/binary"
	"bytes"
	"encoding/gob"
)

func HandlePPPoED(current *packet.Packet, ctx *session.SessionContext) bool {
	p, err := current.GetPPPoED()
	if err != nil {
		fmt.Println(err)
		return false
	}

	ctx.SetSessionID(packet.SwapBytesUint16(p.SessionId))
	ctx.SetEvent(FromPPPCodeToSessionEvent(0, p.Code))
	return true
}

func PreparePPPoEDPacket(pkt *packet.Packet, ctx session.SessionContext, code uint8) error {
	var totalLen uint16
	tags := getTagsFromAttributes(ctx.GetAttributes(), &totalLen)
	if packet.InitEmptyPPPoEDPacket(pkt, uint(totalLen)) == false {
		fmt.Println("Cannot initalizie PPPoED packet!")
		return errors.New("cannot initialize PPPoED packet")
	}
	pppoe := pkt.GetPPPoEDNoTags()
	pppoe.VersionType = 0x11
	pppoe.SessionId = ctx.GetSessionID()
	pppoe.Len = packet.SwapBytesUint16(totalLen)
	pppoe.Tags = tags
	pppoe.Code = code
	pkt.PacketBytesChange(types.EtherLen + types.PPPoELen, convertToBytes(pppoe.Tags))
	return nil
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
		err := enc.Encode(val)
		if err != nil {
			continue
		}
		v := buf.Bytes()[4:]
		tags = append(tags, packet.PPPoETag{Type: packet.PPPoETagMapReversed[key],
										    Len: uint16(len(v)),
											Value: v})
		*totalLen += 4 + uint16(len(v))
		buf.Reset()
	}
	return tags
}