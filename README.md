# l2tp-go

An embeddable Go L2TPv2/PPP library, used by [Overture VPN](https://github.com/eukhlg/overture-vpn).

- L2TPv2 packets, AVPs, reliable control channels, and tunnel/session state
- PPP LCP, PAP, MS-CHAPv2, IPCP, and IPv4
- Datagram engine and injectable UDP listener
- Authentication callbacks, address pools, session limits, and new-tunnel throttling
- Authenticated session events and raw IPv4 packet callbacks

```go
import "github.com/eukhlg/l2tp-go/server"

service, err := server.New(conn, config) // conn is a dedicated net.PacketConn
if err != nil {
    return err
}
defer service.Close()
service.RouteIPv4 = routeIPv4
return service.Serve(ctx)
```

For high-rate embedders the data path speaks
[netio](https://github.com/eukhlg/netio) natively: `server.NewUDPTransport`
puts the socket on netio's batched receive and sharded owned sender,
received packets arrive in pooled `packetbuf.Buffer`s (`DataFrame.Buffer`,
borrowed by `RouteIPv4Owned` until the batch flush), and `OwnedFlowWriter`
frames return packets in place in the caller's `packetbuf.Buffer`.

The library does not configure host routing or require a TUN device. PPP is part
of this module. IPsec is provided independently by
[ipsec-go](https://github.com/eukhlg/ipsec-go); Overture connects the two.

Run `GOWORK=off go test ./...` to test the library independently.

## Migration

This repository contains the L2TP/PPP history extracted from the original
combined l2tp-go application. The complete application history, deployment
files, TUN frontend, and L2TP/IPsec adapter belong to Overture VPN.
The `protocol/l2tp`, `protocol/ppp`, and L2TP `server` package paths are retained.
The old IPsec APIs under `server`, `protocol/isakmp`, and `protocol/esp` move to
ipsec-go. The standalone application and its containers move to Overture VPN.

Library releases use `v`-prefixed semantic versions. The first extracted release is
[v0.3.0](https://github.com/eukhlg/l2tp-go/releases/tag/v0.3.0); old application
tags are not republished as library tags.
