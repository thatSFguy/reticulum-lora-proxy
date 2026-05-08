# AGENTS.md

Guidance for AI agents working in this repo (Claude Code, Codex,
Cursor, Aider, etc.). `CLAUDE.md` carries the same content for tools
that read that filename specifically.

## What this repo is

An **off-spec** LoRa mesh proxy. Sister project to `../reticulum-lora-transport/`,
which is the spec-compliant implementation. This one deliberately
forks from the Reticulum routing model to solve a real deployment
problem: source-routed transports sit idle in single-segment LoRa
meshes because mobile-side path-preference correctly picks direct
paths, but those direct paths fail in marginal RF without graceful
fallback.

The proxy intercepts: it listens promiscuously, learns destinations
from overheard announces, and **promotes** HEADER_1 packets to known
destinations into HEADER_2 packets with itself substituted as the
relay — inserting itself transparently into the path.

## Architectural principles

- **Off-spec by design.** This is NOT a Reticulum transport. Don't
  try to make it spec-compliant — that would defeat its purpose.
  When a behavior would be "wrong" by spec, that's often the point.
- **Wire format compatibility, NOT routing compatibility.** We use
  Reticulum's wire format (HEADER_1/HEADER_2, packet_type, dest_hash,
  transport_id, etc.) so leaves don't need modification. We violate
  the routing semantics.
- **Persist path table to flash.** Post-reboot warmup window was a
  measured pain in the spec-transport repo. Proxies arguably benefit
  even more — they're fully passive, so without persistence they
  contribute nothing useful for the first 5–10 minutes after boot.
- **Channel-aware emission.** Promotions happen only when a path is
  known; multiple proxies on the same segment will each promote, so
  airtime budgeting matters. Suppression window: don't re-promote a
  hash we just emitted.

## Module layout

```
src/                              # firmware glue (carried over from transport repo)
├── main.cpp                      # setup/loop — proxy bring-up
├── Battery / Ble / Led / Storage / Radio / SerialConsole / Config*
└── ...

src/rns/                          # primitives (carried over) + Proxy (new)
├── Proxy.{h,cpp}                 # NEW — the off-spec relay logic
├── Bytes / Crypto / Identity / Packet / Msgpack / Telemetry / Interface
└── tables/
    ├── PathTable      # carried over; gains flash persistence here
    ├── ReverseTable   # carried over; for proof return routing
    └── PacketHashList # carried over; dedup
```

`Transport.{h,cpp}` and its dependent tables (`AnnounceTable`,
`LinkTable`, `Destination`) are present **only** because
`ConfigProtocol::handle_request` takes a `rns::Transport*` parameter
in the carried-over hardware-glue layer. The proxy passes `nullptr`
at runtime, so the spec-transport's symbols are reachable but unused.
A near-term cleanup is to refactor `ConfigProtocol` to take a plain
`Identity*` and drop the carried-over `Transport*` files.

## Constraints (inherited from sister project)

- C++17, exceptions and RTTI enabled.
- No dynamic allocation in radio ISR paths.
- Cooperative multitasking — every `tick()` non-blocking.
- BLE/SPI coexistence: SPI must yield to SoftDevice during BLE
  connection. `loop()` does NOT pause the proxy during BLE.

## When working on this repo

- Reference Reticulum spec for the wire format only. Routing
  semantics here are deliberately divergent — don't cite §12 as
  authoritative for proxy behavior.
- The companion repo at `../reticulum-lora-transport/` is the
  source of truth for hardware glue. Bug fixes / improvements to
  Battery / Radio / BLE / Config protocol should generally land
  there first and then be carried over.
- Keep firmware glue (`src/*.cpp` outside `rns/`) as close as
  practical to the sister repo so improvements track easily.
- The "transparent proxy" behavior is the whole point — do not
  introduce mechanisms that make the proxy require explicit
  addressing by the source. If you find yourself doing that, ask
  why — you may be drifting toward the sister project.
- When `AGENTS.md` and `CLAUDE.md` drift, AGENTS.md is canonical;
  update both to match.
