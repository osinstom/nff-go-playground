// Package 'bngcp' provides types and methods implementing BNG Control Plane object.
package bngcp

import (
	"sync"
	"nff-go-playground/app/session"
	"fmt"
	"github.com/intel-go/nff-go/types"
	"nff-go-playground/app/common"
	"nff-go-playground/app/system"

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
	NetworkDriver	 common.RxTxDriver
	// name of network interface used by this application.
	NetworkInterface string
	// MAC address of network interface used by this application.
	macAddress 		 types.MACAddress
	// IP Address of network interface used by this application.
	ipAddress 		 types.IPv4Address
	// Session Manager instance
	SessionManager   session.SessionManager
}

func (app *BNGControlPlane) SetMACAddress(mac types.MACAddress) {
	app.macAddress = mac
}

func (app *BNGControlPlane) GetMACAddress() types.MACAddress {
	return app.macAddress
}

func (app *BNGControlPlane) SetIPAddress(ip types.IPv4Address) {
	app.ipAddress = ip
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

func (app *BNGControlPlane) Configure() error {

	// If DPDK is used, don't retrieve MAC and IP address programmatically
	if app.NetworkDriver == common.DPDK {
		return nil
	}

	mac, err := system.GetMACAddressOfInterface(app.NetworkInterface)
	if err != nil {
		return err
	}
	app.macAddress = mac

	ipAddr, err := system.GetIPAddressOfInterface(app.NetworkInterface)
	if err != nil {
		return err
	}
	app.SetIPAddress(ipAddr)


	return nil
}

