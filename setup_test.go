package dns64

import (
	"testing"

	"github.com/mholt/caddy"
)

func TestSetupDns64(t *testing.T) {
	tests := []struct {
		inputUpstreams string
		shouldErr      bool
	}{
		{
			`dns64`,
			false,
		},
		{
			`dns64 {
    upstream 8.8.8.8
}`,
			false,
		},
		{
			`dns64 {
    prefix 64:ff9b::/96
}`,
			false,
		},
		{
			`dns64 {
    prefix 64:ff9b::/32
}`,
			false,
		},
		{
			`dns64 {
    prefix 64:ff9b::/52
}`,
			true,
		},
		{
			`dns64 {
    prefix 64:ff9b::/104
}`,
			true,
		},
		{
			`dns64 {
    prefix 8.8.8.8/24
}`,
			true,
		},
		{
			`dns64 {
    upstream 8.8.8.8 8.8.4.4
}`,
			false,
		},
		{
			`dns64 {
    upstream some_not_useable_domain
}`,
			true,
		},
		{
			`dns64 {
    prefix 64:ff9b::/96
    upstream 8.8.8.8
}`,
			false,
		},
		{
			`dns64 foobar {
    prefix 64:ff9b::/96
    upstream 8.8.8.8
}`,
			true,
		},
		{
			`dns64 foobar`,
			true,
		},
		{
			`dns64 {
    foobar
}`,
			true,
		},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.inputUpstreams)
		_, _, err := dns64Parse(c)
		if (err != nil) != test.shouldErr {
			t.Errorf("Test %d expected %v error, got %v for %s", i+1, test.shouldErr, err, test.inputUpstreams)
		}
	}
}
