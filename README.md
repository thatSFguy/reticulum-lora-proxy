# reticulum-lora-proxy

Off-spec **transparent** LoRa mesh proxy for the SX1262 / nRF52840
class of hardware. Listens promiscuously to all LoRa traffic on the
configured channel, tracks destinations it has heard announce, and on
overhearing a HEADER_1 packet to a known destination it re-emits the
packet as HEADER_2 with itself substituted as the relay — racing
the dedup window so the destination consumes the relayed copy and
replies back through the proxy.

## Why this exists

Reticulum's spec'd transport node is **source-routed**: the originator
picks the path based on its local path table and addresses the relay
explicitly via `transport_id`. That works beautifully when there's
exactly one viable path (TCP-backed hub topologies, geographic
extension across long-haul backhaul). It works **poorly** in
single-segment LoRa meshes where leaves are within direct RF range of
each other:

- The mobile correctly picks "direct" over "via T" (fewest hops).
- When direct paths fail in marginal RF, the mobile has no via-T
  entry to fall back to and gives up.
- The transport in the middle has perfect line-of-sight to both
  endpoints and could trivially deliver the packet, but the protocol
  gives it no way to step in.

This proxy steps in. It's a deliberate fork from spec — vanilla
Reticulum implementations may behave unexpectedly when this proxy is
on the segment. Trade-offs accepted; details in [docs/architecture.md](docs/architecture.md).

## Sister project

The companion Reticulum-spec-compliant transport implementation
lives at [reticulum-lora-transport](https://github.com/thatSFguy/reticulum-lora-transport).
That repo is the authoritative spec implementation; this one is the
deployment-pragmatic fork.

## Hardware

Same as the transport firmware:

- **XIAO_nRF52840** + Wio-SX1262 (the bring-up target).
- **ProMicroDIY** (Nice!Nano-style nRF52840 + Ebyte E22-900M30S).
- **RAK4631** (WisBlock Core nRF52840 + integrated SX1262).

Flash via the same web flasher: <https://thatsfguy.github.io/reticulum-lora-webclient/flasher.html>.

## Status

**Initial scaffolding** — `Proxy` class skeleton in place, hourly
telemetry beacon framework wired, hardware/BLE/serial config inherited
from the transport repo. Promotion logic and persistent path table
land in subsequent commits.

## License

Same terms as the sister project (TBD).
