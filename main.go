package main

import (
	"fmt"
	"nff-go-playground/app"
	"github.com/intel-go/nff-go/flow"
	"nff-go-playground/app/common"
)

// Main function. It should:
// 1) Initialize and flush logs.
// 2) Parse command line flags.
// 3) Handle interrupts/errors.
func main() {
	fmt.Println("App started.")
	defer func(){
		fmt.Println("Closing app.")
	}()

	appContext := app.AppContext{
		InterfaceName: "eth0",
		Driver: common.AF_PACKET,
	}
	flow.CheckFatal(app.Run(appContext))
}

