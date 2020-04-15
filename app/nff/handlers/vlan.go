package handlers

import (
	"nff-go-playground/app/session"
	"github.com/intel-go/nff-go/packet"
)

// Read VLAN Tag from the L2 header and remove VLAN tag.
// Note that this function handles only single-tagged packets. Double-VLAN architecture is not supported.
func HandleVLAN(current *packet.Packet, ctx *session.SessionContext) {
	vlan := current.ParseL3CheckVLAN()
	if vlan == nil {  // if there is no VLAN tag, skip handleL2 function.
		return
	}
	ctx.SetVLANID(vlan.GetVLANTagIdentifier())
	current.RemoveVLANTag()
}

