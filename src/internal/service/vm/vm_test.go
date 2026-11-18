package vm

import "testing"

func TestParseUUID(t *testing.T) {
	for _, in := range []string{"0d5f0a7e-1c2b-4d3e-8f9a-0b1c2d3e4f5a", "0d5f0a7e1c2b4d3e8f9a0b1c2d3e4f5a"} {
		u, ok := ParseUUID(in)
		if !ok {
			t.Fatalf("%q not parsed", in)
		}
		if FormatUUID(u) != "0d5f0a7e-1c2b-4d3e-8f9a-0b1c2d3e4f5a" {
			t.Fatalf("round trip %q -> %q", in, FormatUUID(u))
		}
	}
	for _, in := range []string{"", "Windows 11", "0d5f0a7e-1c2b-4d3e-8f9a-0b1c2d3e4f5", "0d5f0a7e-1c2b4-d3e-8f9a-0b1c2d3e4f5a", "zz5f0a7e-1c2b-4d3e-8f9a-0b1c2d3e4f5a", "0d5f0a7e--1c2b-4d3e-8f9a-0b1c2d3e4f5a"} {
		if _, ok := ParseUUID(in); ok {
			t.Errorf("%q parsed as UUID", in)
		}
	}
}
