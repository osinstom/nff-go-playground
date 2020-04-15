package bngcp

import (
	"sync"
	"nff-go-playground/app/session"
	"fmt"
	"net"
	"strings"
	"github.com/intel-go/nff-go/types"
)

var once sync.Once

var (
	mainAppInstance *BNGControlPlane
)

const (
	InitFailedMessage = "BNG Control Plane App initialization failed (%v)"
)

// BNGControlPlane is an abstraction of this application. Should be singleton.
// It stores configuration of this application.
type BNGControlPlane struct {
	// name of network interface used by this application.
	NetworkInterface string
	// MAC address of network interface used by this application.
	macAddress 		 types.MACAddress
	// IP Address of network interface used by this application.
	ipAddress 		 types.IPv4Address
	// Session Manager instance
	SessionManager   session.SessionManager
}

func (app *BNGControlPlane) GetMACAddress() types.MACAddress {
	return app.macAddress
}

func (app *BNGControlPlane) GetIPAddress() types.IPv4Address {
	return app.ipAddress
}

// Get singleton instance
func GetBNGControlPlaneInstance() *BNGControlPlane {
	once.Do(func() {
		mainAppInstance = &BNGControlPlane{}
	})
	return mainAppInstance
}

func (app *BNGControlPlane) String() string {
	return fmt.Sprintf(`BNG Control Plane App: NetworkInterface(%s), MAC Address(%s), IPAddress (%s)`,
		app.NetworkInterface,
		app.macAddress.String(),
		app.ipAddress.String())
}

func (app *BNGControlPlane) Init() error {
	intf, err := net.InterfaceByName(app.NetworkInterface)
	if err != nil {
		return fmt.Errorf(InitFailedMessage, err)
	}

	// Get MAC Address
	app.macAddress, err = types.StringToMACAddress(intf.HardwareAddr.String())
	if err != nil {
		return fmt.Errorf(InitFailedMessage, err)
	}

	addrs, err := intf.Addrs()
	if err != nil {
		return fmt.Errorf(InitFailedMessage, err)
	}
	// Assume that there is only one Address
	for _, addr := range addrs {
		if ip := net.ParseIP(strings.Split(addr.String(), "/")[0]); ip != nil {
			ipv4 := ip.To4()
			if ipv4 == nil {
				// it's not IPv4 address
				continue
			}
			app.ipAddress = types.BytesToIPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		}

	}
	if app.ipAddress == 0 {
		return fmt.Errorf(InitFailedMessage, "Interface has no IPv4 address")
	}

	fmt.Println("BNG Control Plane application initialized. ", app.String())

	return nil
}

