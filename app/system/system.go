// Package 'system' provides primitives for interacting with underlying OS.
package system

import (
	"os/exec"
	"fmt"
	"github.com/intel-go/nff-go/types"
	"net"
	"strings"
)

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

func GetMACAddressOfInterface(intfName string) (types.MACAddress, error) {
	var macAddress = types.MACAddress{}

	intf, err := net.InterfaceByName(intfName)
	if err != nil {
		return macAddress, err
	}
	macAddress, err = types.StringToMACAddress(intf.HardwareAddr.String())
	if err != nil {
		return macAddress, err
	}
	return macAddress, nil
}

func GetIPAddressOfInterface(intfName string) (types.IPv4Address, error) {
	var ipAddress types.IPv4Address = 0

	intf, err := net.InterfaceByName(intfName)
	if err != nil {
		return ipAddress, err
	}

	addrs, err := intf.Addrs()
	if err != nil {
		return ipAddress, err
	}
	// Assume that there is only one Address
	for _, addr := range addrs {
		if ip := net.ParseIP(strings.Split(addr.String(), "/")[0]); ip != nil {
			ipv4 := ip.To4()
			if ipv4 == nil {
				// it's not IPv4 address
				continue
			}
			ipAddress = types.BytesToIPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		}

	}
	if ipAddress == 0 {
		return ipAddress, fmt.Errorf( "Interface has no IPv4 address")
	}

	return ipAddress, nil
}


