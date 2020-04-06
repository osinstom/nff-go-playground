package session

import (
	"fmt"
	"github.com/intel-go/nff-go/packet"
)

type SessionHandler interface {
	HandleSessionEvent(ctx SessionContext)
}

type SessionManager struct {
	SendReplyCallback func(ctx SessionContext)
}

func (sm SessionManager) triggerSessionEvent(ctx SessionContext) {
	fmt.Printf("Triggering SessionEvent{ID=%v, SessionID=%v, TransactionID=%v, SessionAttributes=%v}\n",
		ctx.event, ctx.sessionId, ctx.transactionId, ctx.attributes)
	sm.SendReplyCallback(ctx)
}

// TODO: This function is just a prototype for the test purpose. It has to be re-implemented in the future.
func (sm SessionManager) HandleSessionEvent(ctx SessionContext) {
	fmt.Printf("Handling SessionEvent{ID=%v, SessionID=%v, TransactionID=%v, SessionAttributes=%v}\n", ctx.event,
		ctx.sessionId, ctx.transactionId, ctx.attributes)
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
			ctx.event = LCP_ConfAck
		}
		case LCP_ConfAck: {
			ctx.event = CHAPChallenge
			ctx.transactionId = 171
			ctx.attributes = make(map[string]interface{})
			ctx.attributes["CHAP-Secret"] = 0x1154007413920232
			ctx.attributes["CHAP-Name"] = "JUNOS"
		}
		case CHAPResponse: {
			fmt.Println("CHAP Response received")
			ctx.event = CHAPSuccess
			ctx.ResetAttributes()
			ctx.SetAttribute("CHAP-Message", "")
		}
		default: {
			return
		}
	}

	sm.triggerSessionEvent(ctx)
}