package dns64

import (
	"net"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/proxy"

	"github.com/mholt/caddy"
)

var log = clog.NewWithPlugin("hosts")

func init() {
	caddy.RegisterPlugin("dns64", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	prxy, pref, err := dns64Parse(c)
	if err != nil {
		return plugin.Error("dns64", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return DNS64{Next: next, Proxy: prxy, Prefix: pref}
	})

	return nil
}

func dns64Parse(c *caddy.Controller) (proxy.Proxy, *net.IPNet, error) {
	prxy := proxy.Proxy{}
	_, pref, _ := net.ParseCIDR("64:ff9b::/96")

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) > 0 {
			return prxy, pref, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "upstream":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return prxy, pref, c.ArgErr()
				}
				ups, err := dnsutil.ParseHostPortOrFile(args...)
				if err != nil {
					return prxy, pref, err
				}
				prxy = proxy.NewLookup(ups)
			case "prefix":
				if !c.NextArg() {
					return prxy, pref, c.ArgErr()
				}
				_, pref, err := net.ParseCIDR(c.Val())

				// test for valid prefix
				n, total := pref.Mask.Size()
				if total != 128 {
					return prxy, pref, c.Errf("'%s' not a valid IPv6 address", pref)
				}
				if n%8 != 0 || n < 32 || n > 96 {
					return prxy, pref, c.Errf("'%s' not a valid prefix length", pref)
				}

				if err != nil {
					return prxy, pref, err
				}
			default:
				return prxy, pref, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	return prxy, pref, nil
}
