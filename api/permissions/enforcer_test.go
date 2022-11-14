package permissions

import (
	"testing"
)

func TestIPMultipleMatch_ipv4(t *testing.T) {
	t.Run(
		"Testing simple IPv4 with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("192.0.2.1", "192.0.2.0/24")
			if result == false {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
	t.Run(
		"Testing gtw address with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("192.0.2.0", "192.0.2.0/24")
			if result == false {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
	t.Run(
		"Testing broadcast address with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("192.0.2.255", "192.0.2.0/24")
			if result == false {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
	t.Run(
		"Testing invalid ipv4 with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("192.0.2.256", "192.0.2.0/24")
			if result == true {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
}

func TestIPMultipleMatch_ipv6(t *testing.T) {
	t.Run(
		"Testing simple IPv4 with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("2001:DB8::1", "2001:DB8::/32")
			if result == false {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
	t.Run(
		"Testing gtw address with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("2001:DB8::0", "2001:DB8::/32")
			if result == false {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
	t.Run(
		"Testing broadcast address with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:DB8::/32")
			if result == false {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
	t.Run(
		"Testing invalid ipv4 with CIDR /24",
		func(t *testing.T) {
			result, _ := IPMultipleMatch("2001:0db8:ffff:ffff:ffff:ffff:ffff:fffg", "2001:DB8::/32")
			if result == true {
				t.Fatalf("IPMultipleMatch: check fail with simple IPv4 /24 (%v)", result)
			}
		})
}
