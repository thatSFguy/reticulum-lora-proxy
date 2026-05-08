// src/rns/Proxy.h — transparent LoRa mesh proxy.
//
// **NOT a Reticulum-spec transport node.** This module deliberately
// breaks Reticulum's source-routed model. It listens promiscuously to
// every LoRa packet on the air, tracks destinations it has heard
// announce, and on overhearing a HEADER_1 packet addressed to a known
// destination it re-emits that packet as HEADER_2 with itself
// substituted as the relay (transport_id = our identity_hash). The
// goal is to rescue weak-link transmissions where the source's
// path-table preference correctly picked "direct" but the direct
// path is failing in real RF conditions.
//
// Trade-offs (all known and accepted):
//   - Off-spec: vanilla Reticulum nodes will see the promoted packet
//     as a regular HEADER_2 forwarded by us; their dedup may or may
//     not eat the original direct copy depending on order of arrival.
//   - With multiple proxies near each other, each promotes the same
//     packet → flood-routing-like behavior. Mitigated by a short
//     suppression window (we don't promote a packet hash we just
//     emitted ourselves).
//   - Channel utilization grows with proxy count. Acceptable for
//     small (<20 node) meshes.
//
// What this module does NOT do:
//   - Spec-compliant §12 transport routing.
//   - Path-response generation (§7.2). A proxy isn't a transport;
//     leaves don't address it explicitly.
//   - Link establishment relay. The promotion mechanism handles
//     LINKREQUEST naturally — a HEADER_1 LR gets promoted to HEADER_2
//     just like any other HEADER_1 packet.
//
// Persistence:
//   - The path table IS persisted to flash (post-reboot warmup
//     window was a measured pain point in the spec-transport repo).
//   - Persistence is rate-limited and write-on-change to respect the
//     nRF52's ~10k cycle/page flash wear budget.

#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Packet.h"
#include "rns/tables/PacketHashList.h"
#include "rns/tables/PathTable.h"
#include "rns/tables/ReverseTable.h"

namespace rns {

class Interface;  // forward — non-owning pointer

enum class ProxyTxKind : uint8_t {
    OwnAnnounce,        // periodic self-announce (telemetry beacon)
    PromoteHeader1,     // §X — overheard HEADER_1 promoted to HEADER_2 with us as relay
    ForwardHeader2,     // already-HEADER_2 with us as transport_id, forward as-is
    ProofForward,       // PROOF receipt steered back via reverse_table
    StripToHeader1,     // §12.2.2-equivalent — last hop, strip transport_id
};

using ProxyTxObserverFn = std::function<void(ProxyTxKind)>;

// Lightweight observer for diagnostic logging on Serial. Mirrors the
// transport repo's pattern. Every silent drop fires this, every TX
// fires the TxObserver.
enum class ProxyDropKind : uint8_t {
    PromoteUnknownDest, // overheard HEADER_1 to unknown destination → don't promote
    PromoteSelfEcho,    // would be promoting our own emit → don't (loop)
    PromoteSuppressed,  // already-promoted within suppression window
    ProofUnknown,       // PROOF arrived but no reverse_table entry
};

using ProxyDropObserverFn = std::function<void(ProxyDropKind, const Bytes& subject)>;

class Proxy {
public:
    explicit Proxy(Identity local_identity);

    Proxy(const Proxy&)            = delete;
    Proxy& operator=(const Proxy&) = delete;

    // Register a Bluefruit-style passive listener interface. Proxy
    // doesn't own it.
    void register_interface(Interface* iface);

    // Inbound entry — every received LoRa wire frame goes through
    // here. Increments hops, dedupes, and dispatches to per-type
    // handlers.
    void inbound(Interface* received_on, const Bytes& wire, uint64_t now_ms);

    // Periodic driver — the firmware loop calls this. Drives flash
    // persistence flushes, expiry sweeps, etc.
    void tick(uint64_t now_ms);

    // Identity exposure.
    const Identity& local_identity() const { return _local; }

    // Observer hookups for debug / serial logging.
    void set_tx_observer(ProxyTxObserverFn fn)   { _tx_observer   = std::move(fn); }
    void set_drop_observer(ProxyDropObserverFn fn) { _drop_observer = std::move(fn); }

    // Inspection — used by the telemetry snapshot.
    size_t known_destination_count() const { return _paths.size(); }
    uint32_t promoted_count()        const { return _stats.promoted; }
    uint32_t forwarded_count()       const { return _stats.forwarded_h2; }
    uint32_t proofs_returned_count() const { return _stats.proofs_returned; }

private:
    Identity         _local;
    PathTable        _paths;
    PacketHashList   _hashlist;
    ReverseTable     _reverse_table;
    std::vector<Interface*> _interfaces;

    ProxyTxObserverFn   _tx_observer;
    ProxyDropObserverFn _drop_observer;

    struct Stats {
        uint32_t promoted        = 0;
        uint32_t forwarded_h2    = 0;
        uint32_t stripped_h1     = 0;
        uint32_t proofs_returned = 0;
        uint32_t announces_seen  = 0;
    } _stats;

    // Promotion-suppression: a packet we just emitted (as a promotion
    // or strip-to-h1) shouldn't be re-promoted when our own emit
    // echoes back. Key = post-promotion dedup hash.
    PacketHashList _emitted_hashes;

    void handle_announce(Interface* received_on, const Packet& packet, uint64_t now_ms);
    void handle_header1(Interface* received_on, const Packet& packet, uint64_t now_ms);
    void handle_header2(Interface* received_on, const Packet& packet, uint64_t now_ms);
    void handle_proof  (Interface* received_on, const Packet& packet, uint64_t now_ms);
};

} // namespace rns
