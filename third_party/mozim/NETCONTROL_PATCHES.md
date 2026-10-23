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

Timer and DHCPv4 raw socket registration use Tokio's `AsyncFd::register`, replacing
the deprecated `AsyncFd::new` constructors described in
[tokio-rs/tokio#8587](https://github.com/tokio-rs/tokio/pull/8587). Each unsafe
registration takes ownership of an `OwnedFd` which remains open and unchanged
until deregistration/drop. The timer registration stays local across its await;
the raw socket registration is a private field with no mutable descriptor
replacement or early-close path. Registration errors convert to `std::io::Error`
before the existing DHCP error conversion; failure drops the owned descriptor.

The native crate disables the engine's optional netlink integration and passes
the index/MAC from its existing rtnetlink implementation. This avoids a second
rtnetlink/packet stack. The crate is a patched dependency, not a workspace member.
No upstream contribution, release or runtime validation is claimed.