# Conditional Proxy

[![GoDoc Widget]][GoDoc]

----

A reverse proxy for golang that allows requests to be blocked/aborted before
being sent upstream.

The `Director` function, unlike the `ReverseProxy` in the `httputil` package,
returns a `bool` that determines whether a `Request` should be sent to the
upstream server or not. If `false` is returned, by default, a 403 response
will be returned. This can be customized via the `CreateResponse` function.
Otherwise, the `ConditionalReverseProxy` behaves exactly the same way as the
`ReverseProxy` from `httputil`.

Requires Go 1.12+.

[GoDoc]: https://godoc.org/github.com/sporkmonger/ifproxy
[GoDoc Widget]: https://godoc.org/github.com/sporkmonger/ifproxy?status.svg