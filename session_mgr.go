package main

import (
	"fmt"
)

type SessionEvent uint16

// List of Session Events
const (
	UNKNOWN SessionEvent = iota
	PADI
	PADR
	PADO
	PADS
	LCP_ConfReq
)

type SessionContext struct {
	event           SessionEvent
	subscriberMac   [6]uint8
	sessionId 		uint16
	attributes 		map[string]string
}

type SessionHandler interface {
	HandleSessionEvent(ctx SessionContext)
}

type SessionManager struct {
	SendReplyCallback func(ctx SessionContext)
}

// This function is just a prototype for the test purpose.
// It has to be re-implemented in the future.
func (sm SessionManager) HandleSessionEvent(ctx SessionContext) {
	fmt.Println("Handling session ", ctx)
	switch ctx.event {
		case PADI: {
			ctx.event = PADO
		}
		case PADR: {
			ctx.event = PADS
			ctx.sessionId = 0x1111
		}
		case LCP_ConfReq: {
			fmt.Println("LCP Conf Req")
		}
		default: {
			return
		}
	}
	ctx.attributes = map[string]string{}
	ctx.attributes["Service-Name"] = ""
	ctx.attributes["AC-Name"] = "cbr_bng1_re0"
	sm.SendReplyCallback(ctx)
}