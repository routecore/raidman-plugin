package vm

import (
	"encoding/xml"
	"errors"
	"reflect"
	"strings"
	"testing"

	libvirt "github.com/digitalocean/go-libvirt"
	"libvirt.org/go/libvirtxml"
)

func iface(name, mac string, addrs ...string) libvirt.DomainInterface {
	di := libvirt.DomainInterface{Name: name}
	if mac != "" {
		di.Hwaddr = libvirt.OptString{mac}
	}
	for _, a := range addrs {
		typ := int32(libvirt.IPAddrTypeIpv4)
		if strings.Contains(a, ":") {
			typ = int32(libvirt.IPAddrTypeIpv6)
		}
		di.Addrs = append(di.Addrs, libvirt.DomainIPAddr{Type: typ, Addr: a, Prefix: 24})
	}
	return di
}

func TestSourceConstants(t *testing.T) {
	// The old code passed 2 believing it was the agent; it is ARP.
	if libvirt.DomainInterfaceAddressesSrcLease != 0 || libvirt.DomainInterfaceAddressesSrcAgent != 1 || libvirt.DomainInterfaceAddressesSrcArp != 2 {
		t.Fatal("libvirt source constants changed")
	}
	if !reflect.DeepEqual(ipSources, []libvirt.DomainInterfaceAddressesSource{1, 0, 2}) {
		t.Fatalf("source order = %v, want agent, lease, arp", ipSources)
	}
}

func TestIpsByMAC(t *testing.T) {
	agent := []libvirt.DomainInterface{
		iface("lo", "00:00:00:00:00:00", "127.0.0.1", "::1"),
		iface("Ethernet", "52:54:00:AB:CD:01", "fe80::1c2b:3d4e:5f60:7182", "169.254.10.20", "192.168.1.50", "2001:db8::50", "192.168.1.50"),
		iface("Ethernet 2", "52:54:00:ab:cd:02", "10.0.0.7"),
		iface("docker0", "02:42:ac:11:00:01", "0.0.0.0", "224.0.0.1"),
		iface("tun0", ""),
	}
	got := ipsByMAC(agent)
	want := map[string][]string{
		"52:54:00:ab:cd:01": {"192.168.1.50", "2001:db8::50"},
		"52:54:00:ab:cd:02": {"10.0.0.7"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ipsByMAC = %v, want %v", got, want)
	}
}

func TestUsableIP(t *testing.T) {
	for _, s := range []string{"192.168.1.5", "10.0.0.1", "2001:db8::1", "fd00::5", "::ffff:192.168.1.9"} {
		if _, ok := usableIP(s); !ok {
			t.Errorf("%s rejected", s)
		}
	}
	for _, s := range []string{"127.0.0.1", "127.1.2.3", "::1", "169.254.1.1", "fe80::1", "0.0.0.0", "::", "224.0.0.251", "ff02::1", "", "not-an-ip", "192.168.1.5/24"} {
		if _, ok := usableIP(s); ok {
			t.Errorf("%s accepted", s)
		}
	}
	if a, _ := usableIP("::ffff:192.168.1.9"); a.String() != "192.168.1.9" {
		t.Errorf("v4-mapped not unmapped: %s", a)
	}
}

func TestResolveNICIPs(t *testing.T) {
	const nic1, nic2 = "52:54:00:AB:CD:01", "52:54:00:ab:cd:02"
	type call = libvirt.DomainInterfaceAddressesSource

	t.Run("agent answers every NIC: one query", func(t *testing.T) {
		var calls []call
		got := resolveNICIPs([]string{nic1, nic2}, ipSources, func(src call) ([]libvirt.DomainInterface, error) {
			calls = append(calls, src)
			return []libvirt.DomainInterface{
				iface("lo", "00:00:00:00:00:00", "127.0.0.1"),
				iface("eth0", nic1, "192.168.1.50"),
				iface("eth1", nic2, "10.0.0.7", "fe80::1"),
			}, nil
		})
		if len(calls) != 1 || calls[0] != libvirt.DomainInterfaceAddressesSrcAgent {
			t.Errorf("calls = %v", calls)
		}
		want := map[string][]string{"52:54:00:ab:cd:01": {"192.168.1.50"}, "52:54:00:ab:cd:02": {"10.0.0.7"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("no agent: lease then ARP, each once", func(t *testing.T) {
		var calls []call
		got := resolveNICIPs([]string{nic1, nic2}, ipSources, func(src call) ([]libvirt.DomainInterface, error) {
			calls = append(calls, src)
			switch src {
			case libvirt.DomainInterfaceAddressesSrcAgent:
				return nil, libvirt.Error{Code: 86, Message: "Guest agent is not responding"}
			case libvirt.DomainInterfaceAddressesSrcLease:
				// virbr0 NIC has a lease; the bridged one does not.
				return []libvirt.DomainInterface{iface("vnet1", nic2, "192.168.122.20")}, nil
			default:
				return []libvirt.DomainInterface{
					iface("vnet0", nic1, "192.168.1.50"),
					iface("vnet1", nic2, "192.168.122.99"), // already resolved by lease: ignored
				}, nil
			}
		})
		if !reflect.DeepEqual(calls, []call{1, 0, 2}) {
			t.Errorf("calls = %v", calls)
		}
		want := map[string][]string{"52:54:00:ab:cd:01": {"192.168.1.50"}, "52:54:00:ab:cd:02": {"192.168.122.20"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("agent only reports loopback: falls through", func(t *testing.T) {
		var calls []call
		got := resolveNICIPs([]string{nic1}, ipSources, func(src call) ([]libvirt.DomainInterface, error) {
			calls = append(calls, src)
			if src == libvirt.DomainInterfaceAddressesSrcAgent {
				return []libvirt.DomainInterface{iface("lo", "00:00:00:00:00:00", "127.0.0.1"), iface("eth0", nic1, "169.254.3.4")}, nil
			}
			if src == libvirt.DomainInterfaceAddressesSrcArp {
				return []libvirt.DomainInterface{iface("vnet0", nic1, "192.168.1.51")}, nil
			}
			return nil, errors.New("no leases")
		})
		if len(calls) != 3 || got["52:54:00:ab:cd:01"][0] != "192.168.1.51" {
			t.Errorf("calls=%v got=%v", calls, got)
		}
	})

	t.Run("nothing found: empty map, every source once", func(t *testing.T) {
		n := 0
		got := resolveNICIPs([]string{nic1, "bogus"}, ipSources, func(call) ([]libvirt.DomainInterface, error) {
			n++
			return nil, nil
		})
		if n != 3 || len(got) != 0 {
			t.Errorf("n=%d got=%v", n, got)
		}
	})

	t.Run("no NICs or no sources: no query", func(t *testing.T) {
		q := func(call) ([]libvirt.DomainInterface, error) { t.Fatal("queried"); return nil, nil }
		if got := resolveNICIPs(nil, ipSources, q); len(got) != 0 {
			t.Errorf("got %v", got)
		}
		if got := resolveNICIPs([]string{nic1}, nil, q); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
}

func TestSourcesForState(t *testing.T) {
	noAgent := []libvirt.DomainInterfaceAddressesSource{libvirt.DomainInterfaceAddressesSrcLease, libvirt.DomainInterfaceAddressesSrcArp}
	cases := []struct {
		st    libvirt.DomainState
		agent bool
		want  []libvirt.DomainInterfaceAddressesSource
	}{
		{libvirt.DomainRunning, true, ipSources},
		{libvirt.DomainRunning, false, noAgent},
		{libvirt.DomainBlocked, true, ipSources},
		{libvirt.DomainPaused, true, noAgent},
		{libvirt.DomainPmsuspended, true, noAgent},
		{libvirt.DomainShutoff, true, nil},
		{libvirt.DomainShutdown, true, nil},
		{libvirt.DomainCrashed, true, nil},
		{libvirt.DomainNostate, true, nil},
	}
	for _, c := range cases {
		if got := sourcesForState(uint8(c.st), c.agent); !reflect.DeepEqual(got, c.want) {
			t.Errorf("state %d agent %v: %v, want %v", c.st, c.agent, got, c.want)
		}
	}
}

func TestAgentConnected(t *testing.T) {
	parse := func(channel string) *libvirtxml.DomainDeviceList {
		var d libvirtxml.Domain
		if err := xml.Unmarshal([]byte(`<domain type="kvm"><name>x</name><devices>`+channel+`</devices></domain>`), &d); err != nil {
			t.Fatal(err)
		}
		return d.Devices
	}
	const ch = `<channel type="unix"><source mode="bind"/><target type="virtio" name="org.qemu.guest_agent.0" state="%s"/></channel>`
	if !agentConnected(parse(strings.Replace(ch, "%s", "connected", 1))) {
		t.Error("connected agent not detected")
	}
	if agentConnected(parse(strings.Replace(ch, "%s", "disconnected", 1))) {
		t.Error("disconnected agent treated as connected")
	}
	if agentConnected(parse(`<channel type="spicevmc"><target type="virtio" name="com.redhat.spice.0" state="connected"/></channel>`)) {
		t.Error("spice channel treated as agent")
	}
	if agentConnected(parse(``)) || agentConnected(nil) {
		t.Error("no channel treated as agent")
	}
}
