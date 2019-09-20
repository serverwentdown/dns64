// Package dns64 implements a plugin that performs DNS64.
package dns64

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/plugin/pkg/upstream"
	"github.com/coredns/coredns/request"
	"github.com/coredns/proxy"

	"github.com/miekg/dns"
)

// DNS64 performs DNS64.
type DNS64 struct {
	*proxy.Proxy
	NativeUpstream *upstream.Upstream
	Next           plugin.Handler
	Prefix         *net.IPNet
	TranslateAll   bool // Not comply with 5.1.1
}

// ServeDNS implements the plugin.Handler interface.
func (d DNS64) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	hijackedWriter := &ResponseWriter{w, d, ctx, r}
	return d.Next.ServeDNS(ctx, hijackedWriter, r)
}

// Name implements the Handler interface.
func (d DNS64) Name() string { return "dns64" }

// ResponseWriter is a response writer that implements DNS64, when an AAAA question returns
// NODATA, it will try and fetch any A records and synthesize the AAAA records on the fly.
type ResponseWriter struct {
	dns.ResponseWriter
	DNS64
	ctx context.Context
	req *dns.Msg
}

// WriteMsg implements the dns.ResponseWriter interface.
func (r *ResponseWriter) WriteMsg(res *dns.Msg) error {
	state := request.Request{W: r, Req: res}

	// Only respond with this when the request came in over IPv6. This is not mentioned in the RFC
	// File an issue if you think we should translate even requests made using IPv4, or have a configuration flag
	if state.Family() == 1 { // If it came in over v4, don't do anything.
		return r.ResponseWriter.WriteMsg(res)
	}

	// Do not modify if question is not AAAA or not of class IN. See 5.1
	if state.QType() != dns.TypeAAAA || state.QClass() != dns.ClassINET {
		return r.ResponseWriter.WriteMsg(res)
	}

	ty, _ := response.Typify(res, time.Now().UTC())

	// Handle NameError normally. See 5.1.2
	if ty == response.NameError {
		return r.ResponseWriter.WriteMsg(res)
	}

	// If results in no error and has AAAA, handle normally. See 5.1.6
	if ty == response.NoError {
		// TranslateAll will disable this behaviour and translate all queries. See 5.1.1
		if hasAAAA(res) && !r.TranslateAll {
			return r.ResponseWriter.WriteMsg(res)
		}
	}

	// Perform Lookup
	var replacement *dns.Msg
	var err error
	if len(*r.Upstreams) > 0 {
		// Use Proxy to lookup
		req := new(dns.Msg)
		req.SetQuestion(state.Name(), dns.TypeA)
		nw := nonwriter.New(state.W)
		_, err = r.Proxy.ServeDNS(r.ctx, nw, req)
		replacement = nw.Msg
	} else {
		// Use NativeUpstream to lookup
		replacement, err = r.NativeUpstream.Lookup(r.ctx, state, state.Name(), dns.TypeA)
	}
	if err != nil {
		return err
	}

	// Modify response.
	r.AnswerRewrite(res, replacement)
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

// AnswerRewrite turns A responses into AAAA responses
func (dns64 DNS64) AnswerRewrite(r *dns.Msg, replacement *dns.Msg) {
	r.MsgHdr.Rcode = dns.RcodeSuccess
	// Extract TTLs
	nsTtl := uint32(600) // Default NS record TTL
	for i := 0; i < len(r.Ns); i++ {
		if r.Ns[i].Header().Rrtype == dns.TypeSOA {
			nsTtl = r.Ns[i].Header().Ttl // Use specified NS record TTL
		}
	}
	// Replace all our AAAA answers with A answers
	r.Answer = replacement.Answer
	for i := 0; i < len(r.Answer); i++ {
		ans := r.Answer[i]
		hdr := ans.Header()
		// All of the answers should be A answers. Ensure that
		if hdr.Rrtype == dns.TypeA {
			aaaa, _ := to6(dns64.Prefix, ans.(*dns.A).A)
			ttl := nsTtl
			// Limit the TTL to the NS record TTL
			if ans.Header().Ttl < ttl {
				ttl = ans.Header().Ttl
			}
			// Replace A answer with a DNS64 AAAA answer
			r.Answer[i] = &dns.AAAA{
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
	// TODO: Explain this
	r.Ns = []dns.RR{}
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

// to6 takes a prefix and IPv4 address and returns an IPv6 address according to RFC 6052.
func to6(prefix *net.IPNet, addr net.IP) (net.IP, error) {
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
