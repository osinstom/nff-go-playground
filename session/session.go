package session

import (
	"fmt"
	"bytes"
	"math"
	"encoding/binary"
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

	// IPCP events
	IPCPConfReq
	IPCPConfAck
	IPCPConfNak
)

// List of Session Attributes
// TODO: create a list of allowed Session Attributes and replace raw string used in the code

type SessionContext struct {
	event           SessionEvent
	subscriberMac   [6]uint8
	sessionId 		uint16
	// Specifies PPP-level transaction identifier.
	// Each response for PPP packet must contain the same identifier as request.
	transactionId   uint8
	attributes 		map[string]interface{}
}

func (ctx *SessionContext) SetEvent(evt SessionEvent) {
	ctx.event = evt
}

func (ctx *SessionContext) GetEvent() SessionEvent {
	return ctx.event
}

func (ctx *SessionContext) SetSubscriberMAC(mac [6]uint8) {
	ctx.subscriberMac = mac
}

func (ctx *SessionContext) GetSubscriberMAC() [6]uint8 {
	return ctx.subscriberMac
}

func (ctx *SessionContext) SetSessionID(sessionId uint16) {
	ctx.sessionId = sessionId
}

func (ctx *SessionContext) GetSessionID() uint16 {
	return ctx.sessionId
}

func (ctx *SessionContext) SetTransactionID(transactionId uint8) {
	ctx.transactionId = transactionId
}

func (ctx *SessionContext) GetTransactionID() uint8 {
	return ctx.transactionId
}

func (ctx *SessionContext) appendPPPoEDAttributes() {
	ctx.attributes = map[string]interface{}{}
	ctx.attributes["Service-Name"] = ""
	ctx.attributes["AC-Name"] = "cbr_bng1_re0"
}

func (ctx *SessionContext) ResetAttributes() {
	ctx.attributes = make(map[string]interface{})
}

func (ctx *SessionContext) GetAttributes() map[string]interface{} {
	return ctx.attributes
}

func (ctx *SessionContext) SetAttribute(key string, value interface{}) {
	if ctx.attributes == nil {
		ctx.ResetAttributes()
	}
	ctx.attributes[key] = value
}

// This function converts session attributes into the []byte representation.
// FIXME: This function has problems with converting some int values
func (ctx SessionContext) GetAttributeAsByteArray(attr string) ([]byte, error) {
	val, ok := ctx.attributes[attr]
	if !ok {
		return nil, fmt.Errorf("attribute '%v' has not been provided", attr)
	}
	var err error
	var bin_buf bytes.Buffer

	switch val.(type) {
		case string: {
			_, err = bin_buf.WriteString(val.(string))
		}
		case []byte: {
			_, err = bin_buf.Write(val.([]byte))
		}
		case int: {
			if val.(int) < math.MaxUint8 {
				err = binary.Write(&bin_buf, binary.BigEndian, uint8(val.(int)))
			} else if val.(int) < math.MaxUint16 {
				err = binary.Write(&bin_buf, binary.BigEndian, uint16(val.(int)))
			} else if val.(int) < math.MaxUint32 {
				err = binary.Write(&bin_buf, binary.BigEndian, uint32(val.(int)))
			} else if val.(int) < math.MaxInt64 {
				err = binary.Write(&bin_buf, binary.BigEndian, uint64(val.(int)))
			}
		}
		default: {
			err = binary.Write(&bin_buf, binary.BigEndian, val)
		}
	}
	if err != nil {
		return nil, err
	}
	return bin_buf.Bytes(), nil
}
