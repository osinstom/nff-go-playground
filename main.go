package main

import (
	"github.com/intel-go/nff-go/flow"
	"fmt"
)

func main() {
	fmt.Println("App started.")
	config := flow.Config{
		DisableScheduler: true,
	}
	err := flow.SystemInit(&config)
	if err != nil {
		fmt.Printf("Some error occured: %v\n", err)
		return
	}
	port := "eth0" // TODO: hardcoded
	firstFlow, err := flow.SetReceiverOS(port)
	flow.CheckFatal(flow.SetSenderOS(firstFlow, port))
	flow.CheckFatal(flow.SystemStart())
}