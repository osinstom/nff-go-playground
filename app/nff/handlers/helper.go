package handlers

import (
	"errors"

	"nff-go-playground/app/session"
	"github.com/intel-go/nff-go/packet"
)

type SessionCode struct {
	Protocol uint16
	Code     uint8
}

var codeSessionEventMap = map[SessionCode]session.SessionEvent {
	// PPPoE Discovery
	SessionCode{0, packet.PADI} 	: session.PADI,
	SessionCode{0, packet.PADO} 	: session.PADO,
	SessionCode{0, packet.PADR} 	: session.PADR,
	SessionCode{0, packet.PADS} 	: session.PADS,

	// Link Control Protocol
	SessionCode{packet.LCP, 0x01} 	: session.LCP_ConfReq,
	SessionCode{packet.LCP, 0x02} 	: session.LCP_ConfAck,

	// Challenge-Handshake Authentication Protocol
	SessionCode{packet.CHAP, packet.CHAPChallengeCode}	: session.CHAPChallenge,
	SessionCode{packet.CHAP, packet.CHAPResponseCode} 	: session.CHAPResponse,
	SessionCode{packet.CHAP, packet.CHAPSuccessCode} 	: session.CHAPSuccess,
	SessionCode{packet.CHAP, packet.CHAPFailureCode} 	: session.CHAPFailure,

	// IP Control Protocol
	SessionCode{packet.IPCP, packet.IPCPConfReqCode}	: session.IPCPConfReq,
	SessionCode{packet.IPCP, packet.IPCPConfAckCode}	: session.IPCPConfAck,
	SessionCode{packet.IPCP, packet.IPCPConfNakCode}	: session.IPCPConfNak,
}

func FromPPPCodeToSessionEvent(protocol uint16, code uint8) session.SessionEvent {
	event, ok := codeSessionEventMap[SessionCode{Protocol: protocol, Code: code}]
	if ok {
		return event
	}
	return session.UNKNOWN
}

func FromSessionEventToSessionCode(evt session.SessionEvent) (uint16, uint8, error) {
	for key, val := range codeSessionEventMap {
		if val == evt {
			return key.Protocol, key.Code, nil
		}
	}
	return 0, 0, errors.New("PPP Code for SessionEvent doesn't exist")
}

func InitPPPoES(pkt *packet.Packet, sessionId uint16, protocol uint16, length uint16) *packet.PPPoESHdr {
	pppoes := pkt.GetPPPoES()
	pppoes.VersionType = 0x11
	pppoes.SessionId = sessionId
	pppoes.Len = length
	pppoes.Code = 0x00
	pppoes.Protocol = protocol
	return pppoes
}

