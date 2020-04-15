package app

import (
	"fmt"
	"os/exec"
	"nff-go-playground/app/nff"
	"nff-go-playground/app/common"
	"nff-go-playground/app/bngcp"
	"nff-go-playground/app/session"
	"nff-go-playground/app/nff/handlers"
)

type AppContext struct {
	InterfaceName string
	Driver		  common.RxTxDriver
}

func disableICMPUnreachable() error {
	out, err := exec.Command("iptables", "-I", "OUTPUT", "-p", "icmp", "--icmp-type",
		"destination-unreachable", "-j", "DROP").Output()
	if err != nil {
		return fmt.Errorf("disabling ICMP Unreachable failed: %s", out)
	}
	return nil
}

// This function disables VLAN offloading for the NIC.
// Note that it should be used only for AF_PACKET interfaces.
// TODO: perhaps it would be better to use make a syscall instead of using system command.
func prepareNIC(name string) error {
	out, err := exec.Command("ethtool", "--offload", name, "txvlan", "off", "rxvlan", "off").Output()
	if err != nil {
		return fmt.Errorf("configuring VLAN offloading for NIC %s failed: %v", name, out)
	}
	return nil
}

func ConfigureAF_PACKETInteface(intf string) error {
	// For VXLAN we should disable ICMP Destination Unreachable. Only for AF_PACKET.
	err := disableICMPUnreachable()
	if err != nil {
		return err
	}
	// TODO: this should be called only for AF_PACKET interface.
	err = prepareNIC(intf)
	if err != nil {
		return err
	}
	return nil
}

func Run(ctx AppContext) error {
	if ctx.Driver == common.AF_PACKET {
		err := ConfigureAF_PACKETInteface(ctx.InterfaceName)
		if err != nil {
			return err
		}
	}

	bng := bngcp.GetBNGControlPlaneInstance()
	bng.NetworkInterface = ctx.InterfaceName
	err := bng.Init()
	if err != nil {
		return err
	}
	bng.SessionManager = session.SessionManager{SendReplyCallback: handlers.Send}

	err = nff.InitNFF(ctx.InterfaceName, ctx.Driver)
	if err != nil {
		return err
	}

	nff.Start()

	return nil
}