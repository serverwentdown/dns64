package dns64

import (
	"net"

	"github.com/coredns/proxy"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/upstream"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyfile"
)

var log = clog.NewWithPlugin("dns64")

func init() {
	caddy.RegisterPlugin("dns64", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	dns64, err := dns64Parse(&c.Dispenser)
	if err != nil {
		return plugin.Error("dns64", err)
	}

	t := dnsserver.GetConfig(c).Handler("trace")
	dns64.Trace = t
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		dns64.Next = next
		return dns64
	})

	for i := range *dns64.Upstreams {
		u := (*dns64.Upstreams)[i]
		c.OnStartup(func() error {
			return u.Exchanger().OnStartup(dns64.Proxy)
		})
		c.OnShutdown(func() error {
			return u.Exchanger().OnShutdown(dns64.Proxy)
		})
		// Register shutdown handlers.
		c.OnShutdown(u.Stop)
	}

	return nil
}

func dns64Parse(c *caddyfile.Dispenser) (DNS64, error) {
	_, defaultPref, _ := net.ParseCIDR("64:ff9b::/96")
	dns64 := DNS64{
		Proxy: &proxy.Proxy{
			Upstreams: &[]proxy.Upstream{},
		},
		NativeUpstream: upstream.New(),
		Prefix:         defaultPref,
		TranslateAll:   false,
	}

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 1 {
			pref, err := parsePrefix(c, args[0])

			if err != nil {
				return dns64, err
			}
			dns64.Prefix = pref
			continue
		}
		if len(args) > 0 {
			return dns64, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "proxy":
				// Fake proxy arguments. Need a better solution
				args := c.RemainingArgs()
				fakeTokens := []caddyfile.Token{}
				for _, arg := range args {
					fakeTokens = append(fakeTokens, caddyfile.Token{
						File: c.File(),
						Line: c.Line(),
						Text: arg,
					})
				}
				fakeDispenser := caddyfile.NewDispenserTokens(c.File(), fakeTokens)
				u, err := proxy.NewStaticUpstream(&fakeDispenser)

				if err != nil {
					return dns64, err
				}
				*dns64.Upstreams = append(*dns64.Upstreams, u)
			case "prefix":
				if !c.NextArg() {
					return dns64, c.ArgErr()
				}
				pref, err := parsePrefix(c, c.Val())

				if err != nil {
					return dns64, err
				}
				dns64.Prefix = pref
			case "translateAll":
				dns64.TranslateAll = true
			default:
				return dns64, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}
	return dns64, nil
}

func parsePrefix(c *caddyfile.Dispenser, addr string) (*net.IPNet, error) {
	_, pref, err := net.ParseCIDR(addr)
	if err != nil {
		return nil, err
	}

	// Test for valid prefix
	n, total := pref.Mask.Size()
	if total != 128 {
		return nil, c.Errf("'%s' not a valid IPv6 address", pref)
	}
	if n%8 != 0 || n < 32 || n > 96 {
		return nil, c.Errf("'%s' not a valid prefix length", pref)
	}

	return pref, nil
}
