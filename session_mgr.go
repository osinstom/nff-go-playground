package main

import (
	"fmt"
)

const (
	PADI = iota
	PADR
	PADO
	PADS
)

type SessionContext struct {
	sessionId 		uint16
	attributes 		map[string]string
}

type SessionHandler interface {
	HandleSessionEvent(ctx SessionContext)
}

type SessionManager struct {
	SendReplyCallback func()
}

func (sm SessionManager) HandleSessionEvent(ctx SessionContext) {
	fmt.Println("Handling session ", ctx.sessionId)
	sm.SendReplyCallback()
}