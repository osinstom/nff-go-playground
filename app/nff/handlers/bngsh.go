package handlers

import (
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/flow"
)

// This function should decapsulate BNG Service Header and return pointer to its payload.
// In case of BNG-CP it should be a pointer to the first byte of PPPoED/PPPoES header.
func HandleBNGServiceHeader(current *packet.Packet, context flow.UserContext) {
	// TODO: not used yet.
}
