// src/main.cpp — reticulum-lora-proxy firmware entry point.
//
// `#ifdef ARDUINO` guards the entire body so native test envs can
// include src/* without trying to compile Arduino-specific code.

#ifdef ARDUINO

#include <Arduino.h>

#include <utility>

#include "Battery.h"
#include "Ble.h"
#include "Config.h"
#include "ConfigProtocol.h"
#include "ConfigStore.h"
#include "Led.h"
#include "Radio.h"
#include "SerialConsole.h"
#include "Storage.h"

#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Proxy.h"
#include "rns/Telemetry.h"

namespace {

constexpr const char* IDENTITY_FILE = "/identity.bin";

// Hourly telemetry beacon — the proxy's heartbeat. Mirrors the
// shape used by the spec-transport telemetry, so the same dashboard
// / decoder works.
constexpr uint64_t TELEMETRY_BEACON_PERIOD_MS = 60ULL * 60ULL * 1000ULL;

rns::Proxy*    g_proxy = nullptr;
rlr::Config    g_cfg;
uint64_t       g_next_telemetry_ms = 0;

rns::Identity load_or_generate_identity() {
    uint8_t priv[64];
    int n = rlr::storage::load_file(IDENTITY_FILE, priv, sizeof(priv));
    if (n == 64) {
        Serial.println(F("rlr-proxy: identity loaded from flash"));
        return rns::Identity::from_private_bytes(rns::Bytes(priv, 64));
    }
    Serial.println(F("rlr-proxy: no stored identity — generating fresh"));
    for (int i = 0; i < 64; ++i) priv[i] = rlr::radio::random_byte();
    if (!rlr::storage::save_file(IDENTITY_FILE, priv, 64)) {
        Serial.println(F("rlr-proxy: WARNING — failed to persist identity"));
    }
    return rns::Identity::from_private_bytes(rns::Bytes(priv, 64));
}

rns::telemetry::Snapshot make_telemetry_snapshot() {
    rns::telemetry::Snapshot s;
    if (g_cfg.latitude_udeg != 0 || g_cfg.longitude_udeg != 0) {
        s.have_position = true;
        s.lat = static_cast<float>(g_cfg.latitude_udeg)  / 1000000.0f;
        s.lon = static_cast<float>(g_cfg.longitude_udeg) / 1000000.0f;
    }
    s.battery_mv          = rlr::battery::read_mv(g_cfg.batt_mult);
    s.route_count         = static_cast<uint16_t>(g_proxy ? g_proxy->known_destination_count() : 0);
    s.packets_forwarded   = g_proxy ? g_proxy->forwarded_count() + g_proxy->promoted_count() : 0;
    // The proxy's "rebroadcast" analogue is the count of HEADER_1
    // promotions we performed — that's the off-spec equivalent of
    // §12.3 announce relay (proves the proxy mechanism is firing).
    s.announces_rebroadcast = g_proxy ? g_proxy->promoted_count() : 0;
    s.data_forwarded      = g_proxy ? g_proxy->forwarded_count() : 0;
    s.inbound_packets     = 0;  // TODO once Proxy exposes parse counter
    s.name                = g_cfg.display_name;
    return s;
}

void emit_telemetry_beacon() {
    if (!g_proxy) return;
    const rns::Bytes payload = rns::telemetry::encode(make_telemetry_snapshot());
    Serial.print(F("rlr: telemetry beacon, payload="));
    Serial.print(payload.size());
    Serial.println(F("B"));
    // TODO: emit as a self-announce with this payload as app_data,
    // once Proxy has the announce-emission helper.
    (void)payload;
}

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(50);
    Serial.println(F("rlr-proxy: setup begin"));

    rlr::led::init();
    rlr::battery::init();

    if (!rlr::storage::init()) {
        Serial.println(F("rlr-proxy: WARNING — storage init failed"));
    }
    if (rlr::config_store::load(g_cfg)) {
        Serial.println(F("rlr-proxy: config loaded from flash"));
    } else {
        Serial.println(F("rlr-proxy: no valid config — using defaults"));
    }

    if (!rlr::radio::init_hardware()) Serial.println(F("rlr-proxy: radio init_hardware FAILED"));
    if (!rlr::radio::begin(g_cfg))    Serial.println(F("rlr-proxy: radio begin() FAILED"));
    if (!rlr::radio::start_rx())      Serial.println(F("rlr-proxy: radio start_rx() FAILED"));

    rns::Identity identity = load_or_generate_identity();

    if (g_cfg.display_name[0] == '\0') {
        const auto& h = identity.identity_hash();
        snprintf(g_cfg.display_name, sizeof(g_cfg.display_name),
                 "Pxy-%02x%02x%02x%02x",
                 (unsigned)h[0], (unsigned)h[1], (unsigned)h[2], (unsigned)h[3]);
        rlr::config_store::save(g_cfg);
        Serial.print(F("rlr-proxy: assigned default name: "));
        Serial.println(g_cfg.display_name);
    }

    g_proxy = new rns::Proxy(std::move(identity));

    g_proxy->set_tx_observer([](rns::ProxyTxKind k) {
        const char* tag = "?";
        switch (k) {
            case rns::ProxyTxKind::OwnAnnounce:    tag = "own-announce";    break;
            case rns::ProxyTxKind::PromoteHeader1: tag = "promote-h1";      break;
            case rns::ProxyTxKind::ForwardHeader2: tag = "fwd-h2";          break;
            case rns::ProxyTxKind::ProofForward:   tag = "fwd-proof";       break;
            case rns::ProxyTxKind::StripToHeader1: tag = "strip-to-h1";     break;
        }
        Serial.print(F("rlr-proxy: tx "));
        Serial.println(tag);
    });

    g_proxy->set_drop_observer([](rns::ProxyDropKind k, const rns::Bytes& subject) {
        const char* tag = "?";
        switch (k) {
            case rns::ProxyDropKind::PromoteUnknownDest: tag = "promote-unknown-dest"; break;
            case rns::ProxyDropKind::PromoteSelfEcho:    tag = "promote-self-echo";    break;
            case rns::ProxyDropKind::PromoteSuppressed:  tag = "promote-suppressed";   break;
            case rns::ProxyDropKind::ProofUnknown:       tag = "proof-unknown";        break;
        }
        Serial.print(F("rlr-proxy: drop "));
        Serial.print(tag);
        if (!subject.empty()) {
            Serial.print(F("  "));
            Serial.print(subject.to_hex().c_str());
        }
        Serial.println();
    });

    if (!rlr::ble::init(g_cfg, /*transport=*/nullptr,
                        [](const rlr::Config& c) { return rlr::config_store::save(c); })) {
        Serial.println(F("rlr-proxy: BLE init failed; Serial-only config available"));
    }

    g_next_telemetry_ms = millis() + TELEMETRY_BEACON_PERIOD_MS;

    Serial.println(F("rlr-proxy: setup complete — Proxy + LoRa + BLE ready"));
}

void loop() {
    const uint64_t now = millis();
    rlr::led::tick(now);

    // Drain the radio FIFO into Proxy.inbound. TODO: wire this once
    // we choose between (a) Interface abstraction reuse from the
    // transport repo or (b) direct Radio→Proxy hand-off.

    if (g_proxy) g_proxy->tick(now);

    rlr::serial_console::tick(g_cfg, /*transport=*/nullptr,
                              [](const rlr::Config& c) { return rlr::config_store::save(c); });
    // BLE has no tick — Bluefruit handles events autonomously.

    if (now >= g_next_telemetry_ms) {
        emit_telemetry_beacon();
        g_next_telemetry_ms = now + TELEMETRY_BEACON_PERIOD_MS;
    }
}

#endif  // ARDUINO
