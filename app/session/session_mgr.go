// Package 'session' provides primitives representing User Session within BNG.
package session

import (
	"fmt"
	"github.com/intel-go/nff-go/packet"
)

//type SessionHandler interface {
//	HandleSessionEvent(ctx SessionContext)
//}

type SessionManager struct {
	SendReplyCallback func(ctx SessionContext)
}

func (sm SessionManager) triggerSessionEvent(ctx SessionContext) {
	// TODO: use log package
	fmt.Printf("Triggering SessionEvent{%v}\n", ctx.String())
	sm.SendReplyCallback(ctx)
}

// TODO: This function is just a prototype for the test purpose. It has to be re-implemented in the future.
func (sm SessionManager) HandleSessionEvent(ctx SessionContext) {
	// TODO: use log package
	fmt.Printf("Handling SessionEvent{%v}\n", ctx.String())
	switch ctx.event {
		case PADI: {
			ctx.event = PADO
			ctx.appendPPPoEDAttributes("", "cbr_bng1_re0")  // FIXME: temp, hardcoded value.
		}
		case PADR: {
			ctx.event = PADS
			ctx.sessionId = 0x1111  // FIXME: temp, hardcoded value.
			ctx.appendPPPoEDAttributes("", "cbr_bng1_re0")  // FIXME: temp, hardcoded value.
			go sm.triggerSessionEvent(ctx)

			ctx.event = LCP_ConfReq
			ctx.transactionId = 55 // new transaction ID
			ctx.ResetAttributes()
			ctx.attributes[packet.MaximumReceiveUnit] = 1492
			ctx.attributes[packet.MagicNumber] = 0x643c9869
		}
		case LCP_ConfReq: {
			ctx.event = LCP_ConfAck
		}
		case LCP_ConfAck: {
			ctx.event = CHAPChallenge
			ctx.transactionId = 171
			ctx.ResetAttributes()
			ctx.attributes["CHAP-Secret"] = 0x1154007413920232
			ctx.attributes["CHAP-Name"] = "JUNOS"
		}
		case CHAPResponse: {
			fmt.Println("CHAP Response received")
			ctx.event = CHAPSuccess
			ctx.ResetAttributes()
			ctx.SetAttribute("CHAP-Message", "")
		}
		case IPCPConfReq: {
			fmt.Println("IPCP Conf Req received!")
			ctx.event = IPCPConfAck
			ctx.SetAttribute("IP-Address", "172.10.0.16")
		}
		default: {
			return
		}
	}

	sm.triggerSessionEvent(ctx)
}