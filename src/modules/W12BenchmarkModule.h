#pragma once

#include "configuration.h"

#ifndef MESHTASTIC_W12_BENCHMARK
#define MESHTASTIC_W12_BENCHMARK 0
#endif

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)

#include "concurrency/OSThread.h"
#include "mesh/MeshModule.h"
#include "mesh/RadioInterface.h"
#include <cstddef>
#include <cstdint>

/**
 * Diagnostic-only, owner-loop W12 throughput benchmark. The wire format is deliberately local to
 * this module: it uses PRIVATE_APP, never persists configuration, and is disabled in normal builds.
 */
class W12BenchmarkModule : public MeshModule, private concurrency::OSThread
{
  public:
    static constexpr uint16_t MAGIC = 0x5731;
    static constexpr uint8_t VERSION = 1;
    static constexpr uint16_t CONTROL_BYTES = 32;
    static constexpr uint16_t DATA_HEADER_BYTES = 24;
    static constexpr uint16_t REPORT_BYTES = 86;
    static constexpr uint16_t DEFAULT_SIZE = 219;
    static constexpr uint16_t MAX_SIZE = 219;
    static constexpr uint32_t MIN_COUNT = 1000;
    static constexpr uint32_t MAX_COUNT = 8192;
    static constexpr uint32_t MAX_DURATION_MS = 10UL * 60UL * 1000UL;
    static constexpr uint16_t MAX_WINDOW = 16;

    enum class Op : uint8_t {
        RESET = 1,
        START = 2,
        STOP = 3,
        SNAPSHOT = 4,
    };

    enum class Kind : uint8_t {
        CONTROL = 1,
        DATA = 2,
        REPORT = 3,
    };

    struct RunConfig {
        uint32_t runId = 0;
        NodeNum source = 0;
        NodeNum destination = 0;
        uint32_t count = 0;
        uint16_t size = 0;
        uint32_t durationMs = 0;
        uint16_t window = 0;
        uint8_t flags = 0;
    };

    struct Stats {
        RunConfig config;
        uint32_t enqueued = 0;
        uint32_t sendFailures = 0;
        uint32_t txStarted = 0;
        uint32_t txSucceeded = 0;
        uint32_t txFailures = 0;
        uint32_t txDropped = 0;
        uint32_t txCancelled = 0;
        uint32_t received = 0;
        uint32_t missing = 0;
        uint32_t duplicates = 0;
        uint32_t corrupt = 0;
        uint32_t outOfRange = 0;
        uint32_t elapsedMs = 0;
        uint32_t goodputBps = 0;
        bool prepared = false;
        bool running = false;
        bool complete = false;
    };

    explicit W12BenchmarkModule();

    /** True only for an armed, well-formed benchmark DATA packet for this run. */
    bool isBenchmarkData(const meshtastic_MeshPacket &mp) const;

    // Active outgoing DATA identity is reserved to exact owner-loop producer allocations.
    bool ownsDataIdentity(const meshtastic_MeshPacket &mp) const;
    bool ownsTx(const meshtastic_MeshPacket *packet) const;

    // The integration layer calls these from the radio lifecycle hook after filtering the packet.
    void onTxStarted(const meshtastic_MeshPacket *packet);
    void onTxFinished(const meshtastic_MeshPacket *packet, RadioInterface::TxState state);

    Stats getStats() const;

    // Public pure wire helpers keep host harnesses independent of object/thread setup.
    static bool decodeControl(const uint8_t *bytes, size_t size, Op &op, RunConfig &config);
    static size_t encodeControl(uint8_t *bytes, size_t capacity, Op op, const RunConfig &config);
    static size_t encodeData(uint8_t *bytes, size_t capacity, const RunConfig &config, uint32_t sequence);
    static bool decodeData(const uint8_t *bytes, size_t size, RunConfig &config, uint32_t &sequence);
    static size_t encodeReport(uint8_t *bytes, size_t capacity, const Stats &stats);
    static bool validConfig(const RunConfig &config);

  protected:
    virtual bool wantPacket(const meshtastic_MeshPacket *p) override;
    virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    virtual meshtastic_MeshPacket *allocReply() override;
    virtual int32_t runOnce() override;

  private:
    static constexpr uint8_t FLAG_RELIABLE = 0x01;
    static constexpr uint8_t DATA_KIND = static_cast<uint8_t>(Kind::DATA);
    static constexpr uint8_t CONTROL_KIND = static_cast<uint8_t>(Kind::CONTROL);
    static constexpr uint8_t REPORT_KIND = static_cast<uint8_t>(Kind::REPORT);
    static constexpr uint16_t BITMAP_BYTES = (MAX_COUNT + 7) / 8;
    static constexpr uint8_t TX_SLOT_COUNT = 16;

    struct TxSlot {
        const meshtastic_MeshPacket *packet = nullptr;
        PacketId id = 0;
        uint32_t sequence = 0;
        bool occupied = false;
        bool started = false;
    };

    RunConfig activeConfig;
    Stats stats;
    uint8_t receivedBitmap[BITMAP_BYTES] = {};
    uint32_t startedAtMs = 0;
    bool receiverWindowStarted = false;
    bool snapshotRequested = false;
    bool snapshotRunMatches = false;
    TxSlot txSlots[TX_SLOT_COUNT] = {};
    uint8_t pendingTxCount = 0;

    bool isLocalControl(const meshtastic_MeshPacket &mp) const;
    bool handleControl(const meshtastic_MeshPacket &mp);
    bool handleData(const meshtastic_MeshPacket &mp);
    bool matchesActiveConfig(const RunConfig &config) const;
    bool matchesDataIdentity(const RunConfig &config) const;
    void resetRun(const RunConfig &config);
    void finishRun();
    void clearBitmap();
    int8_t reserveTxSlot(const meshtastic_MeshPacket *packet, uint32_t sequence);
    bool hasTxCapacity() const;
    TxSlot *findTxSlot(const meshtastic_MeshPacket *packet);
    bool wasReceived(uint32_t sequence) const;
    void markReceived(uint32_t sequence);
    static bool sameConfig(const RunConfig &a, const RunConfig &b);
    static void put16(uint8_t *bytes, uint16_t value);
    static void put32(uint8_t *bytes, uint32_t value);
    static uint16_t get16(const uint8_t *bytes);
    static uint32_t get32(const uint8_t *bytes);
    static uint8_t patternByte(const RunConfig &config, uint32_t sequence, uint16_t offset);
};

extern W12BenchmarkModule *w12BenchmarkModule;

#endif
