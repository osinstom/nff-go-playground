package main

import (
	"fmt"
	"github.com/intel-go/nff-go/packet"
)

type SessionEvent uint16

// List of Session Events
const (
	UNKNOWN SessionEvent = iota
	PADI
	PADR
	PADO
	PADS

	// LCP events
	LCP_ConfReq
	LCP_ConfAck

	// CHAP events
	CHAPChallenge
	CHAPResponse
	CHAPSuccess
	CHAPFailure
)

type SessionContext struct {
	event           SessionEvent
	subscriberMac   [6]uint8
	sessionId 		uint16
	// Specifies PPP-level transaction identifier.
	// Each response for PPP packet must contain the same identifier as request.
	transactionId   uint8
	attributes 		map[string]interface{}
}

type SessionHandler interface {
	HandleSessionEvent(ctx SessionContext)
}

type SessionManager struct {
	SendReplyCallback func(ctx SessionContext)
}

func (ctx *SessionContext) appendPPPoEDAttributes() {
	ctx.attributes = map[string]interface{}{}
	ctx.attributes["Service-Name"] = ""
	ctx.attributes["AC-Name"] = "cbr_bng1_re0"
}

func (sm SessionManager) triggerSessionEvent(ctx SessionContext) {
	sm.SendReplyCallback(ctx)
}

// TODO: This function is just a prototype for the test purpose. It has to be re-implemented in the future.
func (sm SessionManager) HandleSessionEvent(ctx SessionContext) {
	fmt.Println("Handling session ", ctx)
	switch ctx.event {
		case PADI: {
			ctx.event = PADO
			ctx.appendPPPoEDAttributes()
		}
		case PADR: {
			ctx.event = PADS
			ctx.sessionId = 0x1111
			ctx.appendPPPoEDAttributes()
			go sm.triggerSessionEvent(ctx)
			//time.Sleep(2 * time.Second)
			ctx.event = LCP_ConfReq
			ctx.transactionId = 55 // new transaction ID
			ctx.attributes = make(map[string]interface{})
			ctx.attributes[packet.MaximumReceiveUnitName] = 1492
			ctx.attributes[packet.MagicNumberName] = 0x643c9869
		}
		case LCP_ConfReq: {
			fmt.Println("LCP Conf Req")
			ctx.event = LCP_ConfAck
		}
		case LCP_ConfAck: {
			fmt.Println("LCP Conf Ack")
			ctx.event = CHAPChallenge
			ctx.transactionId = 171
			ctx.attributes = make(map[string]interface{})
			ctx.attributes["CHAP-Secret"] = 0x54007413920232
			ctx.attributes["CHAP-Name"] = "JUNOS"
		}
		default: {
			return
		}
	}

	sm.triggerSessionEvent(ctx)
}