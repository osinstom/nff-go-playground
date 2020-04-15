// Package 'cups' provides primitives for control and management of BNG DPs associated with this BNG CP.
package cups

import "github.com/intel-go/nff-go/types"

var BngDpMap = map[BngDp]uint8{}
var BngDpMapReversed = map[uint8]BngDp{} // use reversed map to speed up lookup time for send() function.

type BngDp struct {
	IPAddr types.IPv4Address
	MACAddr types.MACAddress
}

// FIXME: oh shit, to delete!
var BngId uint8
