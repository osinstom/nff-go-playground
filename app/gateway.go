// Package 'app' provides main functionality of the BNG CP.
package app

import (
	"fmt"
	"nff-go-playground/app/nff"
	"nff-go-playground/app/common"
	"nff-go-playground/app/bngcp"
	"nff-go-playground/app/system"
	"nff-go-playground/app/session"
	"nff-go-playground/app/nff/handlers"
)

type AppContext struct {
	InterfaceName string
	Driver		  common.RxTxDriver
}

func InitBngApp(ctx AppContext) (*bngcp.BNGControlPlane, error) {
	bng := bngcp.GetBNGControlPlaneInstance()
	bng.NetworkInterface = ctx.InterfaceName
	bng.NetworkDriver = ctx.Driver
	bng.SessionManager = session.SessionManager{SendReplyCallback: handlers.Send}
	bng.Configure()
	return bng, nil
}

func Run(ctx AppContext) error {
	if ctx.Driver == common.AF_PACKET {
		err := system.ConfigureAF_PACKETInteface(ctx.InterfaceName)
		if err != nil {
			return err
		}
	}

	bng, err := InitBngApp(ctx)
	if err != nil {
		return err
	}

	fmt.Println("BNG Control Plane application initialized. ", bng.String())

	err = nff.InitNFF(bng)
	if err != nil {
		return err
	}

	nff.Start()

	return nil
}