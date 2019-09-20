package dns64

import (
	"testing"

	"net"
)

func WrapperTo6(prefix, address string) (net.IP, error) {
	_, pref, _ := net.ParseCIDR(prefix)
	addr := net.ParseIP(address)

	v6, err := to6(pref, addr)

	return v6, err
}

func TestTo6(t *testing.T) {

	v6, err := WrapperTo6("64:ff9b::/96", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:ff9b::4040:4040" {
		t.Errorf("%d", v6)
	}

	v6, err = WrapperTo6("64:ff9b::/64", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:ff9b::40:4040:4000:0" {
		t.Errorf("%d", v6)
	}

	v6, err = WrapperTo6("64:ff9b::/56", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:ff9b:0:40:40:4040::" {
		t.Errorf("%d", v6)
	}

	v6, err = WrapperTo6("64::/32", "64.64.64.64")
	if err != nil {
		t.Error(err)
	}
	if v6.String() != "64:0:4040:4040::" {
		t.Errorf("%d", v6)
	}

}
