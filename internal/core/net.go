package core

import (
	"fmt"
	"net"
)

// ResponseIPv4 returns the IPv4 address Lantern should advertise to victims
// (for example in a poisoned name-service answer or a WPAD proxy script).
//
// When an interface or address was selected on the command line its resolved
// IPv4 address is used. Otherwise the first non-loopback IPv4 address of the
// host is auto-detected.
func (c Config) ResponseIPv4() (net.IP, error) {
	if c.InterfaceAddress != "" {
		if ip := net.ParseIP(c.InterfaceAddress); ip != nil && ip.To4() != nil {
			return ip.To4(), nil
		}
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("enumerate interface addresses: %w", err)
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 != nil && !ip4.IsLoopback() {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no non-loopback IPv4 address found; use -i to select one")
}
