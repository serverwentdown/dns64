
# dns64

The `dns64` plugin implements the DNS64 IPv6 transition mechanism. From Wikipedia:

> DNS64 describes a DNS server that when asked for a domain's AAAA records, but only finds
> A records, synthesizes the AAAA records from the A records.

The synthesis in only performed if the query came in via IPv6.

## TODO

Not all features required by DNS64 are implemented, only basic AAAA synthesis.

* [ ] Support other `proxy` protocols in the configuration file
  - Requires writing a custom parser for the proxy plugin
* [ ] Support "mapping of separate IPv4 ranges to separate IPv6 prefixes"
* [ ] Resolve PTR records
* [ ] Follow CNAME records
* [ ] Make resolver DNSSEC aware
* [ ] Improve test coverage
* [ ] Improve the hooking method
  - At the moment, the plugin hijacks WriteMsg and does the modifications on the message being written. This very likely can break other plugins especially plugins like DNSSEC. 
  - [ ] What position should the plugin be? 

## Usage

> **The syntax has changed since 20 September 2019**. "upstream" has been renamed to proxy

Translate with the well known prefix. Applies to all queries

```
dns64
```

Use a custom prefix

```
dns64 64:1337::/96
# Or 
dns64 {
    prefix 64:1337::/96
}
```

Use a reverse proxy, with a custom prefix

```
dns64 {
    proxy . 1.1.1.1 1.0.0.1
    prefix 64:1337::/96
}
```

Enable translation even if an existing AAAA record is present

```
dns64 {
    translateAll
}
```

* `prefix` specifies any local IPv6 prefix to use, instead of the well known prefix (64:ff9b::/96)
* `proxy` optionally specifies upstream DNS protocol addresses like the `proxy` plugin

## See Also

RFC 6147

## Installation

See [CoreDNS Documentation](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/) for more information on how to include this plugin. A [DNS64 example](https://github.com/serverwentdown/dns64-build) is available too. 

Here's the summary:

```
package main

import (
	_ "github.com/coredns/coredns/core/plugin"
	_ "github.com/coredns/proxy"
	_ "github.com/serverwentdown/dns64"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
)

var additionalDirectives = []string{
	"dns64",
	"proxy",
}

func init() {
	dnsserver.Directives = append(dnsserver.Directives, additionalDirectives...)
}

func main() {
	coremain.Run()
}
```

