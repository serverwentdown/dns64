// Package dns64 implements a plugin that performs DNS64.
package dns64

import (
	"errors"
	"log"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/plugin/proxy"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

// DNS64 performs DNS64.
type DNS64 struct {
	Next   plugin.Handler
	Proxy  proxy.Proxy
	Prefix *net.IPNet
}

// ServeDNS implements the plugin.Handler interface.
func (d DNS64) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	drr := &ResponseWriter{d, w}
	return d.Next.ServeDNS(ctx, drr, r)
}

// Name implements the Handler interface.
func (d DNS64) Name() string { return "dns64" }

// ResponseWriter is a response writer that implements DNS64, when an AAAA query returns
// NODATA, it will try and fetch any A records and synthesize the AAAA records on the fly.
type ResponseWriter struct {
	DNS64
	dns.ResponseWriter
}

// WriteMsg implements the dns.ResponseWriter interface.
func (r *ResponseWriter) WriteMsg(res *dns.Msg) error {
	// Only respond with this when the request came in over IPv6.
	v4 := false
	if ip, ok := r.RemoteAddr().(*net.UDPAddr); ok {
		v4 = ip.IP.To4() != nil
	}
	if ip, ok := r.RemoteAddr().(*net.TCPAddr); ok {
		v4 = ip.IP.To4() != nil
	}
	if v4 { // if it came in over v4, don't do anything.
		return r.ResponseWriter.WriteMsg(res)
	}

	ty, _ := response.Typify(res, time.Now().UTC())
	if ty != response.NoData {
		return r.ResponseWriter.WriteMsg(res)
	}

    // Make request to upstream
	state := request.Request{W: r, Req: res}
	res2, err := r.Proxy.Lookup(state, state.Name(), dns.TypeA)
	if err != nil {
        log.Printf("[WARNING] Unable to query upstream DNS: %v", err)
		return r.ResponseWriter.WriteMsg(res)
	}

	// Modify response
	res.Answer = res2.Answer
	for i := 0; i < len(res.Answer); i++ {
		ans := res.Answer[i]
		hdr := ans.Header()
		if hdr.Rrtype == dns.TypeA {
			aaaa, err := To6(r.Prefix, ans.(*dns.A).A)
			if err != nil {
				log.Printf("[ERROR] %v", err)
			}
			res.Answer[i] = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   hdr.Name,
					Rrtype: dns.TypeAAAA,
					Class:  hdr.Class,
				},
				AAAA: aaaa,
			}
		}
	}

	return r.ResponseWriter.WriteMsg(res)
}

// Write implements the dns.ResponseWriter interface.
func (r *ResponseWriter) Write(buf []byte) (int, error) {
	log.Printf("[WARNING] Dns64 called with Write: not performing DNS64")
	n, err := r.ResponseWriter.Write(buf)
	return n, err
}

// Hijack implements the dns.ResponseWriter interface.
func (r *ResponseWriter) Hijack() {
	r.ResponseWriter.Hijack()
	return
}

// To6 takes a prefix and IPv4 address and returns an IPv6 address according to RFC 6052.
func To6(prefix *net.IPNet, addr net.IP) (net.IP, error) {
	addr = addr.To4()
	if addr == nil {
		return nil, errors.New("Not a valid IPv4 address")
	}

	n, _ := prefix.Mask.Size()
	// Assumes prefix has been validated during setup
	v6 := make([]byte, 16)
	i, j := 0, 0

	for ; i < n/8; i++ {
		v6[i] = prefix.IP[i]
	}
	for ; i < 8; i, j = i+1, j+1 {
		v6[i] = addr[j]
	}
	if i == 8 {
		i++
	}
	for ; j < 4; i, j = i+1, j+1 {
		v6[i] = addr[j]
	}

	return v6, nil
}
