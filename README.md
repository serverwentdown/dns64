# dns64

The *dns64* plugin implements the DNS64 IPv6 transition mechanism. From Wikipedia:

> DNS64 describes a DNS server that when asked for a domain's AAAA records, but only finds
> A records, synthesizes the AAAA records from the A records.

The synthesis in only performed if the query came in via IPv6.

## Syntax

~~~
dns64 {
    upstream ADDRESS...
    prefix IPV6
}
~~~

* `upstream` specifies the upstream resolver.
* `prefix` specifies any local IPv6 prefix to use, in addition to the well known
  prefix (64:ff9b::/96).

## Examples

In recursive resolver mode:

~~~
# Perform dns64 AAAA synthesizing using 8.8.8.8 for resolving any A 
dns64 {
    upstream 8.8.8.8:53
}
proxy . 8.8.8.8:53
~~~

To make DNS64 resolve authoritatively, do:

~~~
dns64 {
    upstream localhost:53
    # caveat: additional round trip through networking stack
}
file example.com.db
~~~

## See Also

<https://en.wikipedia.org/wiki/IPv6_transition_mechanism#DNS64> and RFC 6147.

## Installation

```
$ go get github.com/coredns/coredns
$ go get github.com/serverwentdown/dns64
$ cd $GOPATH/src/github.com/coredns/coredns
$ vim plugin.cfg
# Add the line dns64:github.com/serverwentdown/dns64 before the hosts middleware
$ go generate
$ go build
$ ./coredns -plugins | grep dns64
```
