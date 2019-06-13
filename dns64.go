// Package dns64 implements a plugin that performs DNS64.
package dns64

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/request"
	"github.com/coredns/proxy"

	"github.com/miekg/dns"
)

// DNS64 performs DNS64.
type DNS64 struct {
	Next         plugin.Handler
	Proxy        proxy.Proxy
	Prefix       *net.IPNet
	translateAll bool
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
	state := request.Request{W: r, Req: res}

	// only respond with this when the request came in over IPv6.
	if state.Family() == 1 { // if it came in over v4, don't do anything.
		return r.ResponseWriter.WriteMsg(res)
	}

	// do not modify if query is not AAAA or not of class IN.
	if state.QType() != dns.TypeAAAA || state.QClass() != dns.ClassINET {
		return r.ResponseWriter.WriteMsg(res)
	}

	// do not modify if there are AAAA records or NameError. continue if NoData or any other error.
	ty, _ := response.Typify(res, time.Now().UTC())
	if ty == response.NoError || ty == response.NameError {
		if hasAAAA(res) && !r.translateAll {
			return r.ResponseWriter.WriteMsg(res)
		}
	}

	// perform request to upstream.
	res2, err := r.Proxy.Lookup(state, state.Name(), dns.TypeA)
	if err != nil {
		log.Warningf("[WARNING] Unable to query upstream DNS: %v", err)
		res.MsgHdr.Rcode = dns.RcodeServerFailure
		return r.ResponseWriter.WriteMsg(res)
	}

	// modify response.
	res.MsgHdr.Rcode = dns.RcodeSuccess
	nsTtl := uint32(600)
	for i := 0; i < len(res.Ns); i++ {
		if res.Ns[i].Header().Rrtype == dns.TypeSOA {
			nsTtl = res.Ns[i].Header().Ttl
		}
	}
	res.Answer = res2.Answer
	for i := 0; i < len(res.Answer); i++ {
		ans := res.Answer[i]
		hdr := ans.Header()
		if hdr.Rrtype == dns.TypeA {
			aaaa, _ := To6(r.Prefix, ans.(*dns.A).A)
			ttl := nsTtl
			if ans.Header().Ttl < ttl {
				ttl = ans.Header().Ttl
			}
			res.Answer[i] = &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   hdr.Name,
					Rrtype: dns.TypeAAAA,
					Class:  hdr.Class,
					Ttl:    ttl,
				},
				AAAA: aaaa,
			}
		}
	}
	res.Ns = []dns.RR{}

	return r.ResponseWriter.WriteMsg(res)
}

// Write implements the dns.ResponseWriter interface.
func (r *ResponseWriter) Write(buf []byte) (int, error) {
	log.Warning("[WARNING] DNS64 called with Write: not performing DNS64")
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
	// assumes prefix has been validated during setup
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

// hasAAAA checks if AAAA records exists in dns.Msg
func hasAAAA(res *dns.Msg) bool {
	for _, a := range res.Answer {
		if a.Header().Rrtype == dns.TypeAAAA {
			return true
		}
	}
	return false
}
