package vm

import (
	"net/netip"
	"strings"

	libvirt "github.com/digitalocean/go-libvirt"
	"libvirt.org/go/libvirtxml"
)

// Address sources in the order they are tried: the guest agent knows every
// address inside the guest; DHCP leases only cover libvirt-managed networks;
// the host ARP table works for bridged guests but only sees IPv4 neighbours
// that have talked recently.
var ipSources = []libvirt.DomainInterfaceAddressesSource{
	libvirt.DomainInterfaceAddressesSrcAgent,
	libvirt.DomainInterfaceAddressesSrcLease,
	libvirt.DomainInterfaceAddressesSrcArp,
}

// addrQueryFunc is libvirt's DomainInterfaceAddresses bound to one domain.
type addrQueryFunc func(src libvirt.DomainInterfaceAddressesSource) ([]libvirt.DomainInterface, error)

// normMAC lowercases a MAC address for comparison; "" for invalid input.
func normMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if len(mac) != 17 {
		return ""
	}
	return mac
}

// usableIP parses an address and drops loopback, link-local, unspecified
// and multicast addresses (the guest's "lo", 169.254/16, fe80::/10).
func usableIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() || a.IsInterfaceLocalMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}

// ipsByMAC groups the usable addresses of a DomainInterfaceAddresses result
// by (lowercase) MAC. Within a MAC, IPv4 comes before IPv6 and the order
// libvirt reported is kept otherwise; duplicates are dropped. Interfaces
// without a MAC (or the guest's all-zero loopback MAC) are ignored.
func ipsByMAC(ifaces []libvirt.DomainInterface) map[string][]string {
	v4 := map[string][]string{}
	v6 := map[string][]string{}
	seen := map[string]bool{}
	for _, iface := range ifaces {
		if len(iface.Hwaddr) == 0 {
			continue
		}
		mac := normMAC(iface.Hwaddr[0])
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		for _, ad := range iface.Addrs {
			a, ok := usableIP(ad.Addr)
			if !ok {
				continue
			}
			s := a.String()
			if seen[mac+"|"+s] {
				continue
			}
			seen[mac+"|"+s] = true
			if a.Is4() {
				v4[mac] = append(v4[mac], s)
			} else {
				v6[mac] = append(v6[mac], s)
			}
		}
	}
	out := map[string][]string{}
	for mac, ips := range v4 {
		out[mac] = append(out[mac], ips...)
	}
	for mac, ips := range v6 {
		out[mac] = append(out[mac], ips...)
	}
	return out
}

// resolveNICIPs returns the usable addresses of each NIC (keyed by the
// lowercase MAC). Each source is queried at most once, and the next source
// only while some NIC still has no address; a NIC takes its addresses from
// the first source that has any for its MAC. Errors (no guest agent, no
// lease database, old libvirt without ARP) just move on to the next source.
func resolveNICIPs(macs []string, sources []libvirt.DomainInterfaceAddressesSource, query addrQueryFunc) map[string][]string {
	result := map[string][]string{}
	pending := map[string]bool{}
	for _, m := range macs {
		if mac := normMAC(m); mac != "" {
			pending[mac] = true
		}
	}
	for _, src := range sources {
		if len(pending) == 0 {
			break
		}
		ifaces, err := query(src)
		if err != nil {
			continue
		}
		byMAC := ipsByMAC(ifaces)
		for mac := range pending {
			if ips := byMAC[mac]; len(ips) > 0 {
				result[mac] = ips
				delete(pending, mac)
			}
		}
	}
	return result
}

// guestAgentChannel is the virtio channel name of the QEMU guest agent.
const guestAgentChannel = "org.qemu.guest_agent.0"

// agentConnected reports whether the live domain XML shows the guest agent
// channel as connected. Unraid's templates always add the channel, so a
// Windows guest without the agent installed would otherwise cost libvirt's
// agent timeout (5 s) on every query.
func agentConnected(devs *libvirtxml.DomainDeviceList) bool {
	if devs == nil {
		return false
	}
	for _, ch := range devs.Channels {
		if ch.Target != nil && ch.Target.VirtIO != nil && ch.Target.VirtIO.Name == guestAgentChannel {
			return ch.Target.VirtIO.State == "connected"
		}
	}
	return false
}

// sourcesForState picks the address sources worth asking for a domain in
// the given libvirt state: none for inactive domains, the guest agent only
// for a running guest whose agent is connected.
func sourcesForState(state uint8, agent bool) []libvirt.DomainInterfaceAddressesSource {
	switch libvirt.DomainState(state) {
	case libvirt.DomainRunning, libvirt.DomainBlocked:
		if agent {
			return ipSources
		}
		return ipSources[1:]
	case libvirt.DomainPaused, libvirt.DomainPmsuspended:
		return ipSources[1:]
	}
	return nil
}
