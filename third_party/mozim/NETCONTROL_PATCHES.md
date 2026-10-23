# Netcontrol DHCP Engine Patch

Runtime sources imported from crates.io `mozim` 0.3.3, licensed Apache-2.0;
the upstream LICENSE, README and source attribution are retained. Upstream
integration fixtures and their module declaration are omitted. No Netcontrol
test code was added.

Local changes: an XID-matched DHCPv4 NAK while awaiting ACK becomes
`ErrorKind::NoLease`; REQUEST, RENEW and REBIND propagate it without retrying
the rejected lease. Netcontrol withdraws the address, owned routes and dynamic
resolver settings, then restarts discovery. Invalid/unrelated packets retain
the engine's existing handling.

The native crate disables the engine's optional netlink integration and passes
the index/MAC from its existing rtnetlink implementation. This avoids a second
rtnetlink/packet stack. The crate is a patched dependency, not a workspace member.
No upstream contribution, release or runtime validation is claimed.