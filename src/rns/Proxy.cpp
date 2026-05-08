#include "rns/Proxy.h"

#include "rns/Crypto.h"
#include "rns/Interface.h"

namespace rns {

namespace {
// dedup key for the wire — same hashable_part SHA256[:16] convention
// the transport repo uses. Lets us spot our own emits when they echo
// back from the air and avoid promoting them again.
Bytes wire_dedup_hash(const Packet& p) {
    return crypto::sha256(p.hashable_part()).slice(0, 16);
}
} // namespace

Proxy::Proxy(Identity local_identity) : _local(std::move(local_identity)) {}

void Proxy::register_interface(Interface* iface) {
    if (iface) _interfaces.push_back(iface);
}

void Proxy::inbound(Interface* received_on, const Bytes& wire, uint64_t now_ms) {
    // §2.4 hops bump on inbound, before parsing. Mutate a copy.
    if (wire.size() < 2) return;
    Bytes bumped = wire;
    if (bumped[1] < 255) bumped[1] = bumped[1] + 1;

    std::optional<Packet> parsed;
    try {
        parsed = Packet::from_wire_bytes(bumped);
    } catch (const std::invalid_argument&) {
        return;
    }
    const Packet& packet = *parsed;

    // Wire-layer dedup. Same packet seen twice → drop the second.
    if (!_hashlist.insert(wire_dedup_hash(packet))) return;

    switch (packet.packet_type()) {
        case Packet::PacketType::ANNOUNCE:
            _stats.announces_seen++;
            handle_announce(received_on, packet, now_ms);
            return;
        case Packet::PacketType::PROOF:
            handle_proof(received_on, packet, now_ms);
            return;
        case Packet::PacketType::DATA:
        case Packet::PacketType::LINKREQUEST:
            if (packet.header_type() == Packet::HeaderType::HEADER_1) {
                handle_header1(received_on, packet, now_ms);
            } else {
                handle_header2(received_on, packet, now_ms);
            }
            return;
    }
}

void Proxy::tick(uint64_t /*now_ms*/) {
    // TODO: drive flash-persistence flushes (rate-limited).
    // TODO: drive periodic own-announce / telemetry beacon.
}

void Proxy::handle_announce(Interface* received_on, const Packet& packet,
                            uint64_t now_ms) {
    // TODO: validate (Identity::validate_announce), update _paths
    // with hops & next_hop = packet.transport_id(). Persistence
    // flush happens in tick().
    (void)received_on; (void)packet; (void)now_ms;
}

void Proxy::handle_header1(Interface* received_on, const Packet& packet,
                           uint64_t now_ms) {
    // The promotion path: if we know a route to this destination, take
    // the original HEADER_1 and re-emit as HEADER_2 with our id as
    // transport_id. This is the off-spec rescue mechanism.
    //
    // TODO: implement promotion logic. Sketch:
    //   1. const PathEntry* path = _paths.get(packet.destination_hash());
    //   2. if (!path) → ProxyDropKind::PromoteUnknownDest, return.
    //   3. Bytes promoted_wire = packet.originator_to_header_2(_local.identity_hash()).wire_bytes();
    //   4. Bytes promoted_hash = wire_dedup_hash(parsed promoted);
    //   5. _emitted_hashes.insert(promoted_hash); // suppression window
    //   6. emit on path->receiving_interface (or all interfaces).
    //   7. Insert reverse_table entry for the eventual proof return.
    (void)received_on; (void)packet; (void)now_ms;
}

void Proxy::handle_header2(Interface* received_on, const Packet& packet,
                           uint64_t now_ms) {
    // If transport_id matches us, we're being addressed as a relay.
    // Forward per §12.2 (replace transport_id with next-hop, OR strip
    // to HEADER_1 on last hop). Reuse the spec-transport's logic
    // here — it's correct for the relay case.
    //
    // TODO: implement. Largely a port of Transport::handle_data_forward
    // and Transport::handle_link_request_forward from the sibling repo.
    (void)received_on; (void)packet; (void)now_ms;
}

void Proxy::handle_proof(Interface* received_on, const Packet& packet,
                         uint64_t now_ms) {
    // Steer the PROOF back via reverse_table. Same algorithm as the
    // spec-transport — destination_hash matches what was forwarded
    // outward, look up reverse entry, emit on received_if.
    //
    // TODO: implement.
    (void)received_on; (void)packet; (void)now_ms;
}

} // namespace rns
