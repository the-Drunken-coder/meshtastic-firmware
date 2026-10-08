#pragma once

#include "configuration.h"

#ifndef MESHTASTIC_W12_BENCHMARK
#define MESHTASTIC_W12_BENCHMARK 0
#endif

#ifndef MESHTASTIC_W12_BENCHMARK_TX_BURST
#define MESHTASTIC_W12_BENCHMARK_TX_BURST 0
#endif

#ifndef MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
#define MESHTASTIC_W12_BENCHMARK_PHASE_TIMING 0
#endif

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)

#include "concurrency/OSThread.h"
#include "mesh/MeshModule.h"
#include "mesh/RadioInterface.h"
#include "mesh/W12BenchmarkHalMetrics.h"
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
    static constexpr uint16_t DIAGNOSTIC_REPORT_BYTES = 233;
    static constexpr uint16_t RADIO_DIAGNOSTIC_REPORT_BYTES = 233;
    static constexpr uint16_t RX_LIVENESS_REPORT_BYTES = 80;
    static constexpr uint16_t PRE_SEND_ATTRIBUTION_REPORT_BYTES = 233;
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    static constexpr uint16_t SPI_YIELD_REPORT_BYTES = 80;
#endif
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    static constexpr uint16_t RADIO_GAPS_REPORT_BYTES = 112;
#endif
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
        SNAPSHOT_DIAGNOSTICS = 5,
        SNAPSHOT_RADIO_DIAGNOSTICS = 6,
        SNAPSHOT_RX_LIVENESS = 7,
        REARM_RX_LIVENESS = 8,
        SNAPSHOT_PRE_SEND_ATTRIBUTION = 9,
        SNAPSHOT_RADIO_GAPS = 10,
#if W12_BENCHMARK_HAL_TIMING_ENABLED
        SNAPSHOT_SPI_YIELD = 11,
        ENABLE_SPI_YIELD = 12,
#endif
    };

    enum class Kind : uint8_t {
        CONTROL = 1,
        DATA = 2,
        REPORT = 3,
        DIAGNOSTICS = 4,
        RADIO_DIAGNOSTICS = 5,
        RX_LIVENESS = 6,
        PRE_SEND_ATTRIBUTION = 7,
        OWNER_RADIO_GAPS = 8,
#if W12_BENCHMARK_HAL_TIMING_ENABLED
        SPI_YIELD = 9,
#endif
    };

    enum class CcaReason : uint8_t {
        NOT_READY = 0,
        RSSI_READ_ERROR = 1,
        RX_IRQ_PENDING = 2,
        RX_ACTIVE = 3,
        RSSI_INVALID = 4,
        ENERGY_BUSY = 5,
        FREE = 6,
    };

    enum class PreSendBusyReason : uint8_t {
        UNKNOWN = 0,
        // This is one primary reason per deferral. BUSY_TX wins when TX and RX are both busy.
        BUSY_TX = 1,
        BUSY_RX_ACTIVE = 2,
        BUSY_RX_IRQ_READ_FAILURE = 3,
    };

    enum class RxDecodeResult : uint8_t { Success, Reject, Opaque };
    enum class RxArmStage : uint8_t { NONE = 0, STANDBY = 1, RX_START = 2, IRQ_MAP = 3, FIFO_CLEAR = 4 };
    enum class RadioPhase : uint8_t { RX_START = 0, CHANNEL_ACTIVE = 1, START_SEND = 2 };
    enum class RxLivenessRearmResult : uint8_t { NEVER_PERFORMED = 0, SOFTWARE_ARMED = 1, SOFTWARE_NOT_ARMED = 2 };
    enum class TxFailureStage : uint8_t {
        UNKNOWN = 0,
        FORCED_COMPLETE_FALSE = 1,
        PREFLIGHT = 2,
        START_TRANSMIT = 3,
        TX_IRQ = 4,
        CLEAR_TX_IRQ = 5,
    };

    struct Diagnostics {
        uint32_t txDelayScheduledAttempts = 0;
        uint32_t txDelayFired = 0;
        uint32_t txDelayScheduleAccepted = 0;
        uint32_t txDelayScheduleRejected = 0;
        uint32_t preCanSendDeferred = 0;
        uint32_t ccaDecisions = 0;
        uint32_t ccaReasons[7] = {};
        uint32_t ccaRssiSampleCount = 0;
        int16_t ccaRssiMinDbm = 127;
        int16_t ccaRssiMaxDbm = -127;
        uint32_t ccaRssiHistogram[8] = {};
        uint32_t queueStartDurationCount = 0;
        uint32_t queueStartDurationSumMs = 0;
        uint32_t queueStartDurationMaxMs = 0;
        uint32_t txDurationCount = 0;
        uint32_t txDurationSumMs = 0;
        uint32_t txDurationMaxMs = 0;
        uint32_t txStarted = 0;
        uint32_t txTerminal = 0;
        uint32_t producerBlockedTotal = 0;
        uint32_t producerQueueFreeZero = 0;
        uint32_t producerQueueWindow = 0;
        uint32_t producerTxCapacity = 0;
        uint32_t rxIrqDone = 0;
        uint32_t rxCrcErrors = 0;
        uint32_t rxLenErrors = 0;
        uint32_t rxHeaderCrcErrors = 0;
        uint32_t rxTimeouts = 0;
        uint32_t rxOtherErrors = 0;
        uint32_t rxReadSuccess = 0;
        uint32_t rxReadFailure = 0;
        uint32_t rxQueueEnqueued = 0;
        uint32_t rxQueueDrop = 0;
        uint32_t rxDecodeSuccess = 0;
        uint32_t rxDecodeReject = 0;
        uint32_t rxDecodeOpaque = 0;
        uint32_t rxAuthAccepted = 0;
        uint32_t moduleReceiveHandlerCount = 0;
        uint32_t moduleReceiveHandlerSumMs = 0;
        uint32_t moduleReceiveHandlerMaxMs = 0;
    };

    struct RadioDiagnostics {
        uint32_t rxArmAttempts = 0;
        uint32_t rxArmSuccesses = 0;
        uint32_t rxArmFailures = 0;
        uint32_t rxStandbyCalls = 0;
        uint32_t rxStandbyFailures = 0;
        int16_t rxStandbyLastResult = 0;
        uint32_t rxStartCalls = 0;
        uint32_t rxStartFailures = 0;
        int16_t rxStartLastResult = 0;
        uint32_t rxStartRetryCalls = 0;
        uint32_t rxIrqMapCalls = 0;
        uint32_t rxIrqMapFailures = 0;
        int16_t rxIrqMapLastResult = 0;
        int16_t rxArmLastResult = 0;
        uint32_t rxStartDurationCountUs = 0;
        uint32_t rxStartDurationSumUs = 0;
        uint32_t rxStartDurationMaxUs = 0;
        uint32_t channelActiveDurationCountUs = 0;
        uint32_t channelActiveDurationSumUs = 0;
        uint32_t channelActiveDurationMaxUs = 0;
        uint32_t startSendDurationCountUs = 0;
        uint32_t startSendDurationSumUs = 0;
        uint32_t startSendDurationMaxUs = 0;
        uint32_t pollCalls = 0;
        uint32_t pollRxChecks = 0;
        uint32_t pollRxReadSuccess = 0;
        uint32_t pollRxReadFailure = 0;
        uint32_t pollRxPending = 0;
        uint32_t pollRxLastFlags = 0;
        int16_t pollRxLastResult = 0;
        uint32_t pollRxFlagsOr = 0;
        uint32_t pollTxChecks = 0;
        uint32_t pollTxPending = 0;
        uint8_t pollTxLastDone = 255;
        uint8_t pollChipStatus0 = 0;
        uint8_t pollChipStatus1 = 0;
        uint8_t pollChipStatusObserved = 0;
        uint32_t pollChipStatusAtMs = 0;
        uint32_t pollChipRxCount = 0;
        uint32_t pollChipNonRxCount = 0;
        uint32_t rxDoneBy5sBucket[12] = {};
        uint32_t lastRxDoneAtMs = 0;
        uint32_t lastRxReadAtMs = 0;
        uint32_t lastRxAuthAtMs = 0;
        bool hasLastRxDone = false;
        bool hasLastRxRead = false;
        bool hasLastRxAuth = false;
        uint8_t rxArmLastStage = 255;
    };

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    struct RadioGapMetric {
        uint32_t count = 0;
        uint32_t minUs = 0;
        uint32_t maxUs = 0;
        uint64_t sumUs = 0;
    };

    struct RadioGapDiagnostics {
        RadioGapMetric ownerRxNotifyToRearmUs;
        RadioGapMetric ownerTxNotifyToStartTransmitCallUs;
        uint32_t rxNotifications = 0;
        uint32_t rxValidDone = 0;
        uint32_t rxInvalid = 0;
        uint32_t rxArmFailures = 0;
        uint32_t txValidDone = 0;
        uint32_t txInvalidIrq = 0;
        uint32_t txStartFailures = 0;
        uint32_t txUnpaired = 0;
        uint32_t intervalRejected = 0;
        bool overflow = false;
        bool txCandidate = false;
        bool txPendingStart = false;
        uint32_t txCandidateAtUs = 0;
        uint32_t txPendingStartUs = 0;
    };
#endif

    struct RxLivenessDiagnostics {
        uint32_t snapshotSequence = 0;
        uint32_t snapshotTimeMs = 0;
        uint32_t rearmCount = 0;
        uint32_t rearmLastTimeMs = 0;
        uint32_t rearmLastDurationUs = 0;
        uint8_t sampleStatus = 0;
        uint8_t sampleSource = 0;
        uint8_t rearmResult = static_cast<uint8_t>(RxLivenessRearmResult::NEVER_PERFORMED);
        uint8_t rearmBeforeState = 0;
        uint8_t rearmAfterState = 0;
        uint32_t rawIrqFlags = 0;
        uint16_t rawStatus = 0;
        int16_t irqReadResult = INT16_MIN;
        uint16_t chipRxPackets = 0;
        uint16_t chipCrcErrors = 0;
        uint16_t chipLenErrors = 0;
        int16_t chipStatsResult = INT16_MIN;
        int16_t rssiDbm = INT16_MIN;
        int16_t rssiReadResult = INT16_MIN;
        uint32_t softwareState = 0;
        bool rearmPerformed = false;
    };

    struct PreSendAttributionDiagnostics {
        struct PhaseTimingMetric {
            uint32_t count = 0;
            uint32_t sum = 0;
            uint32_t max = 0;
        };

        struct PhaseTimingDiagnostics {
            bool available = false;
            PhaseTimingMetric producerSendToMeshUs;
            PhaseTimingMetric burstPrepareUs;
            PhaseTimingMetric burstGuardLateMs;
            PhaseTimingMetric rxGateDecodeUs;
            PhaseTimingMetric pkiCcmEncodeUs;
            PhaseTimingMetric pkiCcmDecodeUs;
            bool pkiCcmAvailable = false;
            // The fixed wire extension carries the aggregate duration triplet. Keep the
            // prepare result split in the board-local diagnostic object so a test can prove
            // both outcomes without spending bytes in the reserved tail.
            uint32_t burstPrepareSuccesses = 0;
            uint32_t burstPrepareFailures = 0;
            uint32_t failedTxCount = 0;
            PacketId failedTxLastPacketId = 0;
            uint32_t failedTxLastSequence = 0;
            uint32_t failedTxLastAtMs = 0;
            uint8_t failedTxLastStage = static_cast<uint8_t>(TxFailureStage::UNKNOWN);
            int16_t failedTxLastRadioResult = 0;
        } phaseTiming;

        uint32_t busyTxDeferrals = 0;
        uint32_t busyRxActiveDeferrals = 0;
        uint32_t busyRxIrqReadFailureDeferrals = 0;
        uint32_t txTimerAccepted = 0;
        uint32_t txTimerDispatches = 0;
        uint32_t txTimerLateCount = 0;
        uint32_t txTimerLateSumMs = 0;
        uint32_t txTimerLateMaxMs = 0;
        uint32_t txTimerOverwritten = 0;
        uint32_t txTimerStale = 0;
        uint32_t txTimerCancelled = 0;
        uint32_t txTimerIrqDisplaced = 0;
        bool txTimerActive = false;
        uint32_t txTimerDueAtMs = 0;
        bool rxSampleValid = false;
        uint8_t rxSampleStatus = 0;
        uint8_t rxDioLevel = 0;
        uint8_t rxBusyLevel = 0;
        uint32_t rxActiveReceiveStartMs = 0;
        uint32_t rxSampledAtMs = 0;
        uint32_t rxRawIrqFlags = 0;
        uint16_t rxRawStatus = 0;
        uint16_t rxFifoLevel = 0;
        uint8_t rxFifoFlags = 0;
        uint8_t txFifoFlags = 0;
        uint16_t rxChipErrors = 0;
        int16_t rxIrqReadResult = INT16_MIN;
        int16_t rxFifoFlagsResult = INT16_MIN;
        int16_t rxFifoLevelResult = INT16_MIN;
        int16_t rxErrorsResult = INT16_MIN;
        uint32_t rxSoftwareState = 0;
        // W12 finite-RX burst counters. These occupy the unused tail of the existing report.
        uint32_t burstArmed = 0;
        uint32_t burstFrames = 0;
        uint32_t burstAborted = 0;
        uint32_t burstCount = 0;
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
    void onTxDelayScheduled(const meshtastic_MeshPacket *packet, bool accepted);
    void onTxDelayScheduled(const meshtastic_MeshPacket *packet, bool accepted, uint32_t dueAtMs);
    void onTxDelayNotification(bool isTxDelay, const meshtastic_MeshPacket *packet);
    void onTxDelayFired(const meshtastic_MeshPacket *packet);
    void onW12BurstArmed(bool startsBurst);
    void onW12BurstFrame();
    void onW12BurstAborted();
    void onProducerSendToMeshDuration(uint32_t elapsedUs);
    void onW12BurstPrepareDuration(uint32_t elapsedUs, bool success);
    void onW12BurstGuardLateness(uint32_t nowMs, uint32_t dueAtMs);
    void onRxGateDecodeDuration(uint32_t elapsedUs);
    void onPkiCcmEncodeTiming(uint32_t count, uint32_t sumUs, uint32_t maxUs);
    void onPkiCcmDecodeTiming(uint32_t count, uint32_t sumUs, uint32_t maxUs);
    void onTxFailureObserved(const meshtastic_MeshPacket *packet, TxFailureStage stage, int16_t radioResult);
    void onPreCanSendDeferred(const meshtastic_MeshPacket *packet);
    void onPreCanSendDeferred(const meshtastic_MeshPacket *packet, PreSendBusyReason reason);
    void onCcaDecision(CcaReason reason);
    void onCcaRssiSample(int16_t rssiDbm);
    void onRxIrq(bool readOk, bool rxDone, bool crcError, bool lenError, bool headerCrcError, bool timeout, bool otherError);
    void onRxRead(bool success);
    void onRxQueueEnqueued();
    void onRxQueueDrop();
    void onRxDecode(RxDecodeResult result);
    void onRxAuthenticated();
    void onModuleReceiveHandlerDuration(uint32_t elapsedMs);
    void onRxArmAttempt();
    void onRxArmStage(RxArmStage stage, int16_t result, bool retry = false);
    void onRxArmFinished(int16_t result, RxArmStage failureStage);
    void onRadioPhase(RadioPhase phase, uint32_t elapsedUs);
    void onRadioPoll();
    void onRadioPollRx(int16_t result, uint32_t flags, bool pending, uint16_t rawStatus = 0);
    void onRadioPollTx(bool pending);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    void onOwnerRxNotification(uint32_t startedAtUs, uint32_t completedAtUs, uint32_t rxDoneBefore, uint32_t rxDoneAfter,
                               uint32_t armFailuresBefore, uint32_t armFailuresAfter, bool rearmed);
    void onOwnerTxNotification(uint32_t startedAtUs, bool owned, bool valid);
    void onOwnerTxStartTransmitCall(uint32_t nowUs, bool owned);
    void onOwnerTxStartTransmitResult(bool success);
    void onOwnerTxStartTransmitFailure(bool owned);
#endif

    Stats getStats() const;
    Diagnostics getDiagnostics() const { return diagnostics; }
    RadioDiagnostics getRadioDiagnostics() const { return radioDiagnostics; }
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    RadioGapDiagnostics getRadioGapDiagnostics() const { return radioGapDiagnostics; }
#endif
    uint32_t getRadioRxDoneCount() const
    {
        uint32_t count = 0;
        for (const auto bucket : radioDiagnostics.rxDoneBy5sBucket)
            count = UINT32_MAX - count < bucket ? UINT32_MAX : count + bucket;
        return count;
    }
    uint32_t getRadioRxArmFailureCount() const { return radioDiagnostics.rxArmFailures; }
    PreSendAttributionDiagnostics getPreSendAttributionDiagnostics() const { return preSendDiagnostics; }

    // Public pure wire helpers keep host harnesses independent of object/thread setup.
    static bool decodeControl(const uint8_t *bytes, size_t size, Op &op, RunConfig &config);
    static size_t encodeControl(uint8_t *bytes, size_t capacity, Op op, const RunConfig &config);
    static size_t encodeData(uint8_t *bytes, size_t capacity, const RunConfig &config, uint32_t sequence);
    static bool decodeData(const uint8_t *bytes, size_t size, RunConfig &config, uint32_t &sequence);
    static size_t encodeReport(uint8_t *bytes, size_t capacity, const Stats &stats);
    static size_t encodeDiagnosticsReport(uint8_t *bytes, size_t capacity, const Stats &stats, const Diagnostics &diagnostics,
                                          uint8_t pendingTxCount);
    static size_t encodeRadioDiagnosticsReport(uint8_t *bytes, size_t capacity, const Stats &stats,
                                               const RadioDiagnostics &diagnostics, uint8_t pendingTxCount, uint32_t nowMs,
                                               uint32_t radioState);
    static size_t encodeRxLivenessReport(uint8_t *bytes, size_t capacity, const Stats &stats,
                                         const RxLivenessDiagnostics &diagnostics, uint8_t pendingTxCount);
    static size_t encodePreSendAttributionReport(uint8_t *bytes, size_t capacity, const Stats &stats,
                                                 const PreSendAttributionDiagnostics &diagnostics, uint8_t pendingTxCount);
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    static size_t encodeSpiYieldReport(uint8_t *bytes, size_t capacity, const Stats &stats,
                                       const W12BenchmarkHalMetrics::Snapshot &metrics, uint8_t pendingTxCount);
#endif
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    static size_t encodeRadioGapsReport(uint8_t *bytes, size_t capacity, const Stats &stats,
                                        const RadioGapDiagnostics &diagnostics, uint8_t pendingTxCount);
#endif
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
        uint32_t queuedAtMs = 0;
        uint32_t startedAtMs = 0;
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
        TxFailureStage failureStage = TxFailureStage::UNKNOWN;
        int16_t failureRadioResult = INT16_MIN;
#endif
    };

    RunConfig activeConfig;
    Stats stats;
    uint8_t receivedBitmap[BITMAP_BYTES] = {};
    uint32_t startedAtMs = 0;
    bool receiverWindowStarted = false;
    bool snapshotRequested = false;
    bool snapshotRunMatches = false;
    bool diagnosticSnapshotRequested = false;
    bool diagnosticSnapshotRunMatches = false;
    bool radioDiagnosticSnapshotRequested = false;
    bool radioDiagnosticSnapshotRunMatches = false;
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    bool radioGapsSnapshotRequested = false;
    bool radioGapsSnapshotRunMatches = false;
    bool radioGapRunLatched = false;
#endif
    uint32_t radioDiagnosticStartMs = 0;
    bool radioDiagnosticWindowStarted = false;
    TxSlot txSlots[TX_SLOT_COUNT] = {};
    uint8_t pendingTxCount = 0;
    Diagnostics diagnostics;
    RadioDiagnostics radioDiagnostics;
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    RadioGapDiagnostics radioGapDiagnostics;
#endif
    RxLivenessDiagnostics rxLivenessDiagnostics;
    PreSendAttributionDiagnostics preSendDiagnostics;
    const meshtastic_MeshPacket *trackedTxTimerPacket = nullptr;
    PacketId trackedTxTimerId = 0;
    uint32_t trackedTxTimerDueAtMs = 0;
    bool trackedTxTimerActive = false;
    bool rxLivenessSnapshotRequested = false;
    bool rxLivenessSnapshotRunMatches = false;
    bool rxLivenessRearmUsed = false;
    bool preSendSnapshotRequested = false;
    bool preSendSnapshotRunMatches = false;
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    bool spiYieldArmed = false;
    bool spiYieldWindowValid = false;
    bool spiYieldFrozen = false;
    bool spiYieldSnapshotRequested = false;
    bool spiYieldSnapshotRunMatches = false;
#endif

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
    void producerBlocked(uint32_t &reasonCounter);
    bool collectDiagnostics() const;
    bool collectTxLifecycleDiagnostics() const;
    bool collectRadioDiagnostics() const;
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    bool collectRadioGapDiagnostics() const;
    void finalizeOwnerTxCandidate();
#endif
    bool captureRxLiveness();
    bool capturePreSendAttribution();
    bool performRxLivenessRearm();
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    void freezeSpiYieldTiming();
#endif
    static void saturatingIncrement(uint32_t &value);
    static void saturatingAdd(uint32_t &value, uint32_t amount);
    static void recordPhaseTiming(PreSendAttributionDiagnostics::PhaseTimingMetric &metric, uint32_t sample);
    static void recordPhaseTimingAggregate(PreSendAttributionDiagnostics::PhaseTimingMetric &metric, uint32_t count,
                                           uint32_t sumUs, uint32_t maxUs);
};

extern W12BenchmarkModule *w12BenchmarkModule;

#endif
