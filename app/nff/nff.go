// Package 'nff' provides primitives for initializing and performing packet processing.
package nff

import (
	"fmt"
	"nff-go-playground/app/nff/handlers"
	"nff-go-playground/app/session"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/types"
	"github.com/intel-go/nff-go/packet"
	"nff-go-playground/app/cups"
	"nff-go-playground/app/common"
	"nff-go-playground/app/bngcp"
)

// FlowContext allows to pass data to the NFF Handler.
type FlowContext struct {
	SessionManager session.SessionManager
}

func (ctx FlowContext) Copy() interface{} {
	return FlowContext{
		SessionManager: ctx.SessionManager,
	}
}

func (ctx FlowContext) Delete() {}


// Initializes NFF Go functions.
func InitNFF(app *bngcp.BNGControlPlane) error {

	config := flow.Config{
		// For control plane application it's better to process packets sequentially.
		BurstSize: 1,
	}
	switch app.NetworkDriver {
		case common.AF_PACKET: {
			config.DPDKArgs = []string{"--no-pci", "--vdev=eth_af_packet0,iface=" + app.NetworkInterface}
		}
	}

	err := flow.SystemInit(&config)
	if err != nil {
		fmt.Printf("Some error occured: %v\n", err)
		return err
	}

	context := new(FlowContext)
	context.SessionManager = app.SessionManager

	firstFlow, err := flow.SetReceiver(0)
	if err != nil {
		fmt.Println(err)
		return err
	}
	flow.CheckFatal(flow.SetHandler(firstFlow, handlers.HandleVXLAN, nil))
	// TODO: implement support for BNG SH header here.
	//flow.CheckFatal(flow.SetHandler(firstFlow, handleBNGServiceHeader, context))
	flow.CheckFatal(flow.SetHandlerDrop(firstFlow, handlePPPoE, context))
	flow.CheckFatal(flow.SetSender(firstFlow, 0))
	return nil
}

func Start() {
	flow.CheckFatal(flow.SystemStart())
}

// TODO: refactor this function, because it looks ugly
 func handlePPPoE(current *packet.Packet, ctx flow.UserContext) bool {
 	flowContext := ctx.(FlowContext)
 	var sessionCtx session.SessionContext
 
 	// FIXME: temporary solution, should be handled by shared
 	sessionCtx.SetBngDpID(cups.BngId)
 
 	// As NFF Go does not provide the way to share the state between handler I put VLAN handler here.
 	handlers.HandleVLAN(current, &sessionCtx)
 
 	current.ParseL3()
 
 	if current.Ether.EtherType == types.SwapPPPoEDNumber {
 		ok := handlers.HandlePPPoED(current, &sessionCtx)
 		if !ok {
 			return false
 		}
 	} else if current.Ether.EtherType == types.SwapPPPoESNumber {
 		p := current.GetPPPoES()
 		ppp := current.GetPPPNoOptions()
 		sessionCtx.SetTransactionID(ppp.Identifier)
 		switch packet.SwapBytesUint16(p.Protocol) {
 			case packet.LCP: {
 				handlers.HandleLCP(current, &sessionCtx)
 			}
 			case packet.CHAP: {
 				handlers.HandleCHAP(current, ppp, &sessionCtx)
 			}
 			case packet.IPCP: {
 				ipcp, err := current.GetIPCP()
 				if err != nil {
 					fmt.Println(err)
 					return false
 				}
 				handlers.HandleIPCP(ipcp, &sessionCtx)
 			}
 			default: {
 				return false
 			}
 		}
 		sessionCtx.SetSessionID(packet.SwapBytesUint16(p.SessionId))
 		sessionCtx.SetEvent(handlers.FromPPPCodeToSessionEvent(packet.SwapBytesUint16(p.Protocol), ppp.Code))
 	} else {
 		// Should drop
 		return false
 	}
 	sessionCtx.SetSubscriberMAC(current.Ether.SAddr)

 	// handle session event in separate goroutine
 	go flowContext.SessionManager.HandleSessionEvent(sessionCtx)
 
 	return false
 }



