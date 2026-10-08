#include "W12BenchmarkModule.h"

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)

#include "MeshService.h"
#include "NodeDB.h"
#include "Router.h"
#include "Throttle.h"
#include "UptimeClock.h"
#include "mesh/RadioLibInterface.h"
#include <cstring>

W12BenchmarkModule *w12BenchmarkModule = nullptr;

namespace
{
constexpr uint8_t kNoFlags = 0;
constexpr uint32_t kMinimumDurationMs = 60UL * 1000UL;
constexpr int32_t kIdleIntervalMs = 1000;
constexpr int32_t kQueueRetryIntervalMs = 5;
constexpr int32_t kProducerIntervalMs = 0;

bool validOperation(W12BenchmarkModule::Op op)
{
    return op == W12BenchmarkModule::Op::RESET || op == W12BenchmarkModule::Op::START || op == W12BenchmarkModule::Op::STOP ||
           op == W12BenchmarkModule::Op::SNAPSHOT || op == W12BenchmarkModule::Op::SNAPSHOT_DIAGNOSTICS ||
           op == W12BenchmarkModule::Op::SNAPSHOT_RADIO_DIAGNOSTICS || op == W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS ||
           op == W12BenchmarkModule::Op::REARM_RX_LIVENESS || op == W12BenchmarkModule::Op::SNAPSHOT_PRE_SEND_ATTRIBUTION;
}

uint32_t diagnosticAge(bool present, uint32_t timestamp, uint32_t nowMs)
{
    return present ? nowMs - timestamp : UINT32_MAX;
}
} // namespace

W12BenchmarkModule::W12BenchmarkModule()
    : MeshModule("W12Benchmark", meshtastic_PortNum_PRIVATE_APP), concurrency::OSThread("W12Benchmark")
{
    w12BenchmarkModule = this;
}

void W12BenchmarkModule::saturatingIncrement(uint32_t &value)
{
    if (value != UINT32_MAX)
        ++value;
}

void W12BenchmarkModule::saturatingAdd(uint32_t &value, uint32_t amount)
{
    value = UINT32_MAX - value < amount ? UINT32_MAX : value + amount;
}

void W12BenchmarkModule::recordPhaseTiming(PreSendAttributionDiagnostics::PhaseTimingMetric &metric, uint32_t sample)
{
    saturatingIncrement(metric.count);
    saturatingAdd(metric.sum, sample);
    if (sample > metric.max)
        metric.max = sample;
}

void W12BenchmarkModule::recordPhaseTimingAggregate(PreSendAttributionDiagnostics::PhaseTimingMetric &metric, uint32_t count,
                                                    uint32_t sumUs, uint32_t maxUs)
{
    saturatingAdd(metric.count, count);
    saturatingAdd(metric.sum, sumUs);
    if (maxUs > metric.max)
        metric.max = maxUs;
}

void W12BenchmarkModule::put16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = static_cast<uint8_t>(value);
    bytes[1] = static_cast<uint8_t>(value >> 8);
}

void W12BenchmarkModule::put32(uint8_t *bytes, uint32_t value)
{
    for (uint8_t i = 0; i < sizeof(value); i++)
        bytes[i] = static_cast<uint8_t>(value >> (i * 8));
}

uint16_t W12BenchmarkModule::get16(const uint8_t *bytes)
{
    return static_cast<uint16_t>(bytes[0]) | static_cast<uint16_t>(bytes[1]) << 8;
}

uint32_t W12BenchmarkModule::get32(const uint8_t *bytes)
{
    return static_cast<uint32_t>(bytes[0]) | static_cast<uint32_t>(bytes[1]) << 8 | static_cast<uint32_t>(bytes[2]) << 16 |
           static_cast<uint32_t>(bytes[3]) << 24;
}

size_t W12BenchmarkModule::encodeControl(uint8_t *bytes, size_t capacity, Op op, const RunConfig &config)
{
    if (!bytes || capacity < CONTROL_BYTES || !validOperation(op))
        return 0;

    memset(bytes, 0, CONTROL_BYTES);
    put16(bytes, MAGIC);
    bytes[2] = VERSION;
    bytes[3] = static_cast<uint8_t>(op);
    put32(bytes + 4, config.runId);
    put32(bytes + 8, config.source);
    put32(bytes + 12, config.destination);
    put32(bytes + 16, config.count);
    put16(bytes + 20, config.size);
    put32(bytes + 22, config.durationMs);
    put16(bytes + 26, config.window);
    bytes[28] = config.flags;
    return CONTROL_BYTES;
}

bool W12BenchmarkModule::decodeControl(const uint8_t *bytes, size_t size, Op &op, RunConfig &config)
{
    if (!bytes || size != CONTROL_BYTES || get16(bytes) != MAGIC || bytes[2] != VERSION || bytes[29] != 0 || bytes[30] != 0 ||
        bytes[31] != 0)
        return false;

    const auto decodedOp = static_cast<Op>(bytes[3]);
    if (!validOperation(decodedOp))
        return false;

    config.runId = get32(bytes + 4);
    config.source = get32(bytes + 8);
    config.destination = get32(bytes + 12);
    config.count = get32(bytes + 16);
    config.size = get16(bytes + 20);
    config.durationMs = get32(bytes + 22);
    config.window = get16(bytes + 26);
    config.flags = bytes[28];
    op = decodedOp;
    return true;
}

uint8_t W12BenchmarkModule::patternByte(const RunConfig &config, uint32_t sequence, uint16_t offset)
{
    uint32_t value = config.runId ^ config.source ^ (config.destination * 0x9E3779B9u) ^ (sequence * 0x85EBCA6Bu) ^
                     (static_cast<uint32_t>(offset) * 0xC2B2AE35u);
    value ^= value >> 16;
    value *= 0x7FEB352Du;
    value ^= value >> 15;
    return static_cast<uint8_t>(value);
}

size_t W12BenchmarkModule::encodeData(uint8_t *bytes, size_t capacity, const RunConfig &config, uint32_t sequence)
{
    if (!bytes || config.size < DATA_HEADER_BYTES || config.size > MAX_SIZE || capacity < config.size)
        return 0;

    memset(bytes, 0, config.size);
    put16(bytes, MAGIC);
    bytes[2] = VERSION;
    bytes[3] = static_cast<uint8_t>(Kind::DATA);
    put32(bytes + 4, config.runId);
    put32(bytes + 8, config.source);
    put32(bytes + 12, config.destination);
    put32(bytes + 16, sequence);
    put16(bytes + 20, config.size);
    bytes[22] = config.flags;
    for (uint16_t i = DATA_HEADER_BYTES; i < config.size; i++)
        bytes[i] = patternByte(config, sequence, i);
    return config.size;
}

bool W12BenchmarkModule::decodeData(const uint8_t *bytes, size_t size, RunConfig &config, uint32_t &sequence)
{
    if (!bytes || size < DATA_HEADER_BYTES || size > MAX_SIZE || get16(bytes) != MAGIC || bytes[2] != VERSION ||
        bytes[3] != static_cast<uint8_t>(Kind::DATA) || bytes[23] != 0)
        return false;

    config.runId = get32(bytes + 4);
    config.source = get32(bytes + 8);
    config.destination = get32(bytes + 12);
    sequence = get32(bytes + 16);
    config.size = get16(bytes + 20);
    config.flags = bytes[22];
    return config.size == size;
}

size_t W12BenchmarkModule::encodeReport(uint8_t *bytes, size_t capacity, const Stats &value)
{
    if (!bytes || capacity < REPORT_BYTES)
        return 0;

    memset(bytes, 0, REPORT_BYTES);
    put16(bytes, MAGIC);
    bytes[2] = VERSION;
    bytes[3] = static_cast<uint8_t>(Kind::REPORT);
    put32(bytes + 4, value.config.runId);
    put32(bytes + 8, value.config.source);
    put32(bytes + 12, value.config.destination);
    put32(bytes + 16, value.config.count);
    put16(bytes + 20, value.config.size);
    put32(bytes + 22, value.config.durationMs);
    put16(bytes + 26, value.config.window);
    bytes[28] = value.config.flags;
    bytes[29] = static_cast<uint8_t>((value.prepared ? 1 : 0) | (value.running ? 2 : 0) | (value.complete ? 4 : 0));
    put32(bytes + 30, value.enqueued);
    put32(bytes + 34, value.sendFailures);
    put32(bytes + 38, value.txStarted);
    put32(bytes + 42, value.txSucceeded);
    put32(bytes + 46, value.txFailures);
    put32(bytes + 50, value.txDropped);
    put32(bytes + 54, value.txCancelled);
    put32(bytes + 58, value.received);
    put32(bytes + 62, value.missing);
    put32(bytes + 66, value.duplicates);
    put32(bytes + 70, value.corrupt);
    put32(bytes + 74, value.outOfRange);
    put32(bytes + 78, value.elapsedMs);
    put32(bytes + 82, value.goodputBps);
    return REPORT_BYTES;
}

size_t W12BenchmarkModule::encodeDiagnosticsReport(uint8_t *bytes, size_t capacity, const Stats &value, const Diagnostics &d,
                                                   uint8_t pendingTxCount)
{
    if (!bytes || capacity < DIAGNOSTIC_REPORT_BYTES)
        return 0;

    memset(bytes, 0, DIAGNOSTIC_REPORT_BYTES);
    put16(bytes, MAGIC);
    bytes[2] = VERSION;
    bytes[3] = static_cast<uint8_t>(Kind::DIAGNOSTICS);
    put32(bytes + 4, value.config.runId);
    put32(bytes + 8, value.config.source);
    put32(bytes + 12, value.config.destination);
    put32(bytes + 16, value.elapsedMs);
    bytes[20] = static_cast<uint8_t>((value.prepared ? 1 : 0) | (value.running ? 2 : 0) | (value.complete ? 4 : 0) |
                                     (d.ccaRssiSampleCount ? 8 : 0) | (pendingTxCount ? 16 : 0) |
                                     (value.running || pendingTxCount ? 32 : 0));
    bytes[21] = pendingTxCount;

    put32(bytes + 24, d.txDelayScheduledAttempts);
    put32(bytes + 28, d.preCanSendDeferred);
    put32(bytes + 32, d.ccaDecisions);
    for (uint8_t i = 0; i < 7; i++)
        put32(bytes + 36 + i * sizeof(uint32_t), d.ccaReasons[i]);
    put32(bytes + 64, d.ccaRssiSampleCount);
    put16(bytes + 68, static_cast<uint16_t>(d.ccaRssiMinDbm));
    put16(bytes + 70, static_cast<uint16_t>(d.ccaRssiMaxDbm));
    for (uint8_t i = 0; i < 8; i++)
        put32(bytes + 72 + i * sizeof(uint32_t), d.ccaRssiHistogram[i]);
    put32(bytes + 104, d.queueStartDurationCount);
    put32(bytes + 108, d.queueStartDurationSumMs);
    put32(bytes + 112, d.queueStartDurationMaxMs);
    put32(bytes + 116, d.txDurationCount);
    put32(bytes + 120, d.txDurationSumMs);
    put32(bytes + 124, d.txDurationMaxMs);
    put32(bytes + 128, d.txStarted);
    put32(bytes + 132, d.txTerminal);
    put32(bytes + 136, d.producerBlockedTotal);
    put32(bytes + 140, d.producerQueueFreeZero);
    put32(bytes + 144, d.producerQueueWindow);
    put32(bytes + 148, d.producerTxCapacity);
    put32(bytes + 152, d.rxIrqDone);
    put32(bytes + 156, d.rxCrcErrors);
    put32(bytes + 160, d.rxLenErrors);
    put32(bytes + 164, d.rxHeaderCrcErrors);
    put32(bytes + 168, d.rxTimeouts);
    put32(bytes + 172, d.rxOtherErrors);
    put32(bytes + 176, d.rxReadSuccess);
    put32(bytes + 180, d.rxReadFailure);
    put32(bytes + 184, d.rxQueueEnqueued);
    put32(bytes + 188, d.rxQueueDrop);
    put32(bytes + 192, d.rxDecodeSuccess);
    put32(bytes + 196, d.rxDecodeReject);
    put32(bytes + 200, d.rxDecodeOpaque);
    put32(bytes + 204, d.rxAuthAccepted);
    put32(bytes + 208, d.moduleReceiveHandlerCount);
    put32(bytes + 212, d.moduleReceiveHandlerSumMs);
    put32(bytes + 216, d.moduleReceiveHandlerMaxMs);
    put32(bytes + 220, d.txDelayFired);
    put32(bytes + 224, d.txDelayScheduleAccepted);
    put32(bytes + 228, d.txDelayScheduleRejected);
    return DIAGNOSTIC_REPORT_BYTES;
}

size_t W12BenchmarkModule::encodeRadioDiagnosticsReport(uint8_t *bytes, size_t capacity, const Stats &value,
                                                        const RadioDiagnostics &d, uint8_t pendingTxCount, uint32_t nowMs,
                                                        uint32_t radioState)
{
    if (!bytes || capacity < RADIO_DIAGNOSTIC_REPORT_BYTES)
        return 0;

    memset(bytes, 0, RADIO_DIAGNOSTIC_REPORT_BYTES);
    put16(bytes, MAGIC);
    bytes[2] = VERSION;
    bytes[3] = static_cast<uint8_t>(Kind::RADIO_DIAGNOSTICS);
    put32(bytes + 4, value.config.runId);
    put32(bytes + 8, value.config.source);
    put32(bytes + 12, value.config.destination);
    put32(bytes + 16, value.elapsedMs);
    bytes[20] = static_cast<uint8_t>((value.prepared ? 1 : 0) | (value.running ? 2 : 0) | (value.complete ? 4 : 0) |
                                     (pendingTxCount ? 16 : 0) | ((value.running || pendingTxCount) ? 32 : 0));
    bytes[21] = pendingTxCount;

    put32(bytes + 24, d.rxArmAttempts);
    put32(bytes + 28, d.rxArmSuccesses);
    put32(bytes + 32, d.rxArmFailures);
    put32(bytes + 36, d.rxStandbyCalls);
    put32(bytes + 40, d.rxStandbyFailures);
    put16(bytes + 44, static_cast<uint16_t>(d.rxStandbyLastResult));
    put32(bytes + 46, d.rxStartCalls);
    put32(bytes + 50, d.rxStartFailures);
    put16(bytes + 54, static_cast<uint16_t>(d.rxStartLastResult));
    put32(bytes + 56, d.rxStartRetryCalls);
    put32(bytes + 60, d.rxIrqMapCalls);
    put32(bytes + 64, d.rxIrqMapFailures);
    put16(bytes + 68, static_cast<uint16_t>(d.rxIrqMapLastResult));
    put16(bytes + 70, static_cast<uint16_t>(d.rxArmLastResult));
    put32(bytes + 72, d.rxStartDurationCountUs);
    put32(bytes + 76, d.rxStartDurationSumUs);
    put32(bytes + 80, d.rxStartDurationMaxUs);
    put32(bytes + 84, d.channelActiveDurationCountUs);
    put32(bytes + 88, d.channelActiveDurationSumUs);
    put32(bytes + 92, d.channelActiveDurationMaxUs);
    put32(bytes + 96, d.startSendDurationCountUs);
    put32(bytes + 100, d.startSendDurationSumUs);
    put32(bytes + 104, d.startSendDurationMaxUs);
    put32(bytes + 108, d.pollCalls);
    put32(bytes + 112, d.pollRxChecks);
    put32(bytes + 116, d.pollRxReadSuccess);
    put32(bytes + 120, d.pollRxReadFailure);
    put32(bytes + 124, d.pollRxPending);
    put32(bytes + 128, d.pollRxLastFlags);
    put16(bytes + 132, static_cast<uint16_t>(d.pollRxLastResult));
    put32(bytes + 134, d.pollRxFlagsOr);
    put32(bytes + 138, d.pollTxChecks);
    put32(bytes + 142, d.pollTxPending);
    bytes[146] = d.pollTxLastDone;
    bytes[147] = static_cast<uint8_t>((radioState & 1u) != 0);
    bytes[148] = static_cast<uint8_t>((radioState & 2u) != 0);
    bytes[149] = static_cast<uint8_t>((radioState >> 2) & 0x03u);
    bytes[150] = static_cast<uint8_t>((radioState >> 4) & 0x01u);
    bytes[151] = 255;
    bytes[152] = 0;

    for (uint8_t i = 0; i < 12; i++)
        put32(bytes + 156 + i * sizeof(uint32_t), d.rxDoneBy5sBucket[i]);
    put32(bytes + 204, diagnosticAge(d.hasLastRxDone, d.lastRxDoneAtMs, nowMs));
    put32(bytes + 208, diagnosticAge(d.hasLastRxRead, d.lastRxReadAtMs, nowMs));
    put32(bytes + 212, diagnosticAge(d.hasLastRxAuth, d.lastRxAuthAtMs, nowMs));
    bytes[216] = d.rxArmLastStage;
    bytes[217] = d.pollChipStatus0;
    bytes[218] = d.pollChipStatus1;
    bytes[219] = d.pollChipStatusObserved;
    put32(bytes + 220, diagnosticAge(d.pollChipStatusObserved != 0, d.pollChipStatusAtMs, nowMs));
    put32(bytes + 224, d.pollChipRxCount);
    put32(bytes + 228, d.pollChipNonRxCount);
    return RADIO_DIAGNOSTIC_REPORT_BYTES;
}

size_t W12BenchmarkModule::encodeRxLivenessReport(uint8_t *bytes, size_t capacity, const Stats &value,
                                                  const RxLivenessDiagnostics &d, uint8_t pendingTxCount)
{
    if (!bytes || capacity < RX_LIVENESS_REPORT_BYTES)
        return 0;

    memset(bytes, 0, RX_LIVENESS_REPORT_BYTES);
    put16(bytes, MAGIC);
    bytes[2] = VERSION;
    bytes[3] = static_cast<uint8_t>(Kind::RX_LIVENESS);
    put32(bytes + 4, value.config.runId);
    put32(bytes + 8, value.config.source);
    put32(bytes + 12, value.config.destination);
    put32(bytes + 16, value.elapsedMs);
    bytes[20] = static_cast<uint8_t>((value.prepared ? 1 : 0) | (value.running ? 2 : 0) | (value.complete ? 4 : 0) |
                                     (pendingTxCount ? 16 : 0) | ((value.running || pendingTxCount) ? 32 : 0));
    bytes[21] = pendingTxCount;

    put32(bytes + 24, d.snapshotSequence);
    put32(bytes + 28, d.snapshotTimeMs);
    bytes[32] = d.sampleStatus;
    bytes[33] = d.sampleSource;
    put32(bytes + 34, d.rearmCount);
    bytes[38] = d.rearmResult;
    bytes[39] = d.rearmBeforeState;
    bytes[40] = d.rearmAfterState;
    put32(bytes + 44, d.rearmLastTimeMs);
    put32(bytes + 48, d.rearmLastDurationUs);
    put32(bytes + 52, d.rawIrqFlags);
    put16(bytes + 56, d.rawStatus);
    put16(bytes + 58, static_cast<uint16_t>(d.irqReadResult));
    put16(bytes + 60, d.chipRxPackets);
    put16(bytes + 62, d.chipCrcErrors);
    put16(bytes + 64, d.chipLenErrors);
    put16(bytes + 66, static_cast<uint16_t>(d.chipStatsResult));
    put16(bytes + 68, static_cast<uint16_t>(d.rssiDbm));
    put16(bytes + 70, static_cast<uint16_t>(d.rssiReadResult));
    put32(bytes + 72, d.softwareState);
    return RX_LIVENESS_REPORT_BYTES;
}

size_t W12BenchmarkModule::encodePreSendAttributionReport(uint8_t *bytes, size_t capacity, const Stats &value,
                                                          const PreSendAttributionDiagnostics &d, uint8_t pendingTxCount)
{
    if (!bytes || capacity < PRE_SEND_ATTRIBUTION_REPORT_BYTES)
        return 0;

    memset(bytes, 0, PRE_SEND_ATTRIBUTION_REPORT_BYTES);
    put16(bytes, MAGIC);
    bytes[2] = VERSION;
    bytes[3] = static_cast<uint8_t>(Kind::PRE_SEND_ATTRIBUTION);
    put32(bytes + 4, value.config.runId);
    put32(bytes + 8, value.config.source);
    put32(bytes + 12, value.config.destination);
    put32(bytes + 16, value.elapsedMs);
    bytes[20] = static_cast<uint8_t>((value.prepared ? 1 : 0) | (value.running ? 2 : 0) | (value.complete ? 4 : 0) |
                                     (pendingTxCount ? 16 : 0) | ((value.running || pendingTxCount) ? 32 : 0));
    bytes[21] = pendingTxCount;

    put32(bytes + 24, d.busyTxDeferrals);
    put32(bytes + 28, d.busyRxActiveDeferrals);
    put32(bytes + 32, d.busyRxIrqReadFailureDeferrals);
    put32(bytes + 36, d.txTimerAccepted);
    put32(bytes + 40, d.txTimerDispatches);
    put32(bytes + 44, d.txTimerLateCount);
    put32(bytes + 48, d.txTimerLateSumMs);
    put32(bytes + 52, d.txTimerLateMaxMs);
    put32(bytes + 56, d.txTimerOverwritten);
    put32(bytes + 60, d.txTimerStale);
    put32(bytes + 64, d.txTimerCancelled);
    put32(bytes + 68, d.txTimerIrqDisplaced);
    bytes[72] = static_cast<uint8_t>(d.txTimerActive);
    bytes[73] = static_cast<uint8_t>(d.rxSampleValid);
    bytes[74] = d.rxSampleStatus;
    bytes[75] = d.rxDioLevel;
    bytes[76] = d.rxBusyLevel;
    put32(bytes + 78, d.rxActiveReceiveStartMs);
    put32(bytes + 82, d.rxSampledAtMs);
    put32(bytes + 86, d.rxRawIrqFlags);
    put16(bytes + 90, d.rxRawStatus);
    put16(bytes + 92, d.rxFifoLevel);
    bytes[94] = d.rxFifoFlags;
    bytes[95] = d.txFifoFlags;
    put16(bytes + 96, d.rxChipErrors);
    put16(bytes + 98, static_cast<uint16_t>(d.rxIrqReadResult));
    put16(bytes + 100, static_cast<uint16_t>(d.rxFifoFlagsResult));
    put16(bytes + 102, static_cast<uint16_t>(d.rxFifoLevelResult));
    put16(bytes + 104, static_cast<uint16_t>(d.rxErrorsResult));
    put32(bytes + 106, d.rxSoftwareState);
    put32(bytes + 110, d.txTimerDueAtMs);
    put32(bytes + 114, d.burstArmed);
    put32(bytes + 118, d.burstFrames);
    put32(bytes + 122, d.burstAborted);
    put32(bytes + 126, d.burstCount);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    bytes[178] = static_cast<uint8_t>(d.phaseTiming.available);
    put32(bytes + 130, d.phaseTiming.producerSendToMeshUs.count);
    put32(bytes + 134, d.phaseTiming.producerSendToMeshUs.sum);
    put32(bytes + 138, d.phaseTiming.producerSendToMeshUs.max);
    put32(bytes + 142, d.phaseTiming.burstPrepareUs.count);
    put32(bytes + 146, d.phaseTiming.burstPrepareUs.sum);
    put32(bytes + 150, d.phaseTiming.burstPrepareUs.max);
    put32(bytes + 154, d.phaseTiming.burstGuardLateMs.count);
    put32(bytes + 158, d.phaseTiming.burstGuardLateMs.sum);
    put32(bytes + 162, d.phaseTiming.burstGuardLateMs.max);
    put32(bytes + 166, d.phaseTiming.rxGateDecodeUs.count);
    put32(bytes + 170, d.phaseTiming.rxGateDecodeUs.sum);
    put32(bytes + 174, d.phaseTiming.rxGateDecodeUs.max);
    put32(bytes + 179, d.phaseTiming.failedTxCount);
    put32(bytes + 183, d.phaseTiming.failedTxLastPacketId);
    put32(bytes + 187, d.phaseTiming.failedTxLastSequence);
    put32(bytes + 191, d.phaseTiming.failedTxLastAtMs);
    bytes[195] = d.phaseTiming.failedTxLastStage;
    put16(bytes + 196, static_cast<uint16_t>(d.phaseTiming.failedTxLastRadioResult));
    put32(bytes + 198, d.phaseTiming.pkiCcmEncodeUs.count);
    put32(bytes + 202, d.phaseTiming.pkiCcmEncodeUs.sum);
    put32(bytes + 206, d.phaseTiming.pkiCcmEncodeUs.max);
    put32(bytes + 210, d.phaseTiming.pkiCcmDecodeUs.count);
    put32(bytes + 214, d.phaseTiming.pkiCcmDecodeUs.sum);
    put32(bytes + 218, d.phaseTiming.pkiCcmDecodeUs.max);
    bytes[222] = static_cast<uint8_t>(d.phaseTiming.pkiCcmAvailable);
#endif
    return PRE_SEND_ATTRIBUTION_REPORT_BYTES;
}

bool W12BenchmarkModule::sameConfig(const RunConfig &a, const RunConfig &b)
{
    return a.runId == b.runId && a.source == b.source && a.destination == b.destination && a.count == b.count &&
           a.size == b.size && a.durationMs == b.durationMs && a.window == b.window && a.flags == b.flags;
}

bool W12BenchmarkModule::validConfig(const RunConfig &config)
{
    return config.runId != 0 && config.source != 0 && config.destination != 0 && config.source != config.destination &&
           !isBroadcast(config.source) && !isBroadcast(config.destination) && config.count >= MIN_COUNT &&
           config.count <= MAX_COUNT && config.size == DEFAULT_SIZE && config.durationMs == kMinimumDurationMs &&
           config.window > 0 && config.window <= MAX_WINDOW && config.flags == kNoFlags;
}

bool W12BenchmarkModule::isLocalControl(const meshtastic_MeshPacket &mp) const
{
    return mp.which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
           mp.decoded.portnum == meshtastic_PortNum_PRIVATE_APP && mp.from == 0 && getFrom(&mp) == nodeDB->getNodeNum() &&
           isToUs(&mp) &&
           (mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL ||
            mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_API);
}

bool W12BenchmarkModule::matchesActiveConfig(const RunConfig &config) const
{
    return stats.prepared && sameConfig(config, activeConfig);
}

bool W12BenchmarkModule::matchesDataIdentity(const RunConfig &config) const
{
    return stats.prepared && config.runId == activeConfig.runId && config.source == activeConfig.source &&
           config.destination == activeConfig.destination && config.size == activeConfig.size &&
           config.flags == activeConfig.flags;
}

bool W12BenchmarkModule::isBenchmarkData(const meshtastic_MeshPacket &mp) const
{
    const bool localProducer = nodeDB->getNodeNum() == activeConfig.source &&
                               (mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL ||
                                mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_API);
    const bool radioReceipt = nodeDB->getNodeNum() == activeConfig.destination &&
                              mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA &&
                              mp.from == activeConfig.source && mp.pki_encrypted && !mp.via_mqtt;
    if (!stats.prepared || mp.which_payload_variant != meshtastic_MeshPacket_decoded_tag ||
        mp.decoded.portnum != meshtastic_PortNum_PRIVATE_APP || mp.to != activeConfig.destination ||
        getFrom(&mp) != activeConfig.source || (!localProducer && !radioReceipt))
        return false;

    RunConfig frameConfig;
    uint32_t sequence;
    if (!decodeData(mp.decoded.payload.bytes, mp.decoded.payload.size, frameConfig, sequence))
        return false;
    return matchesDataIdentity(frameConfig);
}

bool W12BenchmarkModule::ownsDataIdentity(const meshtastic_MeshPacket &mp) const
{
    if (!stats.prepared || nodeDB->getNodeNum() != activeConfig.source || getFrom(&mp) != activeConfig.source ||
        mp.to != activeConfig.destination || mp.which_payload_variant != meshtastic_MeshPacket_decoded_tag ||
        mp.decoded.portnum != meshtastic_PortNum_PRIVATE_APP)
        return false;
    RunConfig frameConfig;
    uint32_t sequence;
    return decodeData(mp.decoded.payload.bytes, mp.decoded.payload.size, frameConfig, sequence) &&
           matchesDataIdentity(frameConfig);
}

bool W12BenchmarkModule::ownsTx(const meshtastic_MeshPacket *packet) const
{
    if (!packet)
        return false;
    for (const auto &slot : txSlots) {
        if (slot.occupied && slot.packet == packet && slot.id == packet->id)
            return true;
    }
    return false;
}

void W12BenchmarkModule::onTxStarted(const meshtastic_MeshPacket *packet)
{
    if (!stats.prepared || !packet)
        return;

    TxSlot *slot = findTxSlot(packet);
    if (slot && !slot->started) {
        slot->started = true;
        slot->startedAtMs = Time::getMillis();
        stats.txStarted++;
        if (collectTxLifecycleDiagnostics()) {
            const uint32_t elapsed = slot->startedAtMs - slot->queuedAtMs;
            saturatingIncrement(diagnostics.txStarted);
            saturatingIncrement(diagnostics.queueStartDurationCount);
            saturatingAdd(diagnostics.queueStartDurationSumMs, elapsed);
            if (elapsed > diagnostics.queueStartDurationMaxMs)
                diagnostics.queueStartDurationMaxMs = elapsed;
        }
    }
}

void W12BenchmarkModule::onTxFinished(const meshtastic_MeshPacket *packet, RadioInterface::TxState state)
{
    if (!stats.prepared || !packet)
        return;

    TxSlot *slot = findTxSlot(packet);
    if (!slot)
        return;

    if (trackedTxTimerActive && trackedTxTimerPacket == packet && trackedTxTimerId == packet->id) {
        saturatingIncrement(preSendDiagnostics.txTimerCancelled);
        trackedTxTimerActive = false;
        trackedTxTimerPacket = nullptr;
        trackedTxTimerId = 0;
        trackedTxTimerDueAtMs = 0;
        preSendDiagnostics.txTimerActive = false;
        preSendDiagnostics.txTimerDueAtMs = 0;
    }

    const bool collect = collectTxLifecycleDiagnostics();
    const uint32_t finishedAtMs = Time::getMillis();
    if (collect) {
        saturatingIncrement(diagnostics.txTerminal);
        if (slot->started) {
            const uint32_t elapsed = finishedAtMs - slot->startedAtMs;
            saturatingIncrement(diagnostics.txDurationCount);
            saturatingAdd(diagnostics.txDurationSumMs, elapsed);
            if (elapsed > diagnostics.txDurationMaxMs)
                diagnostics.txDurationMaxMs = elapsed;
        }
    }

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (state == RadioInterface::TxState::Failed) {
        preSendDiagnostics.phaseTiming.available = true;
        saturatingIncrement(preSendDiagnostics.phaseTiming.failedTxCount);
        preSendDiagnostics.phaseTiming.failedTxLastPacketId = packet->id;
        preSendDiagnostics.phaseTiming.failedTxLastSequence = slot->sequence;
        preSendDiagnostics.phaseTiming.failedTxLastAtMs = finishedAtMs;
        // The exact physical slot carries an explicit observed failure site, if one exists.
        // Generic terminal callbacks remain unknown; failure alone cannot identify a cause.
        preSendDiagnostics.phaseTiming.failedTxLastStage = static_cast<uint8_t>(slot->failureStage);
        preSendDiagnostics.phaseTiming.failedTxLastRadioResult = slot->failureRadioResult;
    }
#endif

    switch (state) {
    case RadioInterface::TxState::Sent:
        stats.txSucceeded++;
        break;
    case RadioInterface::TxState::Failed:
    case RadioInterface::TxState::Rejected:
        stats.txFailures++;
        break;
    case RadioInterface::TxState::Dropped:
        stats.txDropped++;
        break;
    case RadioInterface::TxState::Cancelled:
        stats.txCancelled++;
        break;
    default:
        break;
    }

    *slot = TxSlot{};
    if (pendingTxCount != 0)
        pendingTxCount--;
}

void W12BenchmarkModule::onTxDelayScheduled(const meshtastic_MeshPacket *packet, bool accepted)
{
    if (!collectTxLifecycleDiagnostics() || !findTxSlot(packet))
        return;
    saturatingIncrement(diagnostics.txDelayScheduledAttempts);
    saturatingIncrement(accepted ? diagnostics.txDelayScheduleAccepted : diagnostics.txDelayScheduleRejected);
}

void W12BenchmarkModule::onTxDelayScheduled(const meshtastic_MeshPacket *packet, bool accepted, uint32_t dueAtMs)
{
    if (!collectTxLifecycleDiagnostics() || !findTxSlot(packet))
        return;

    saturatingIncrement(diagnostics.txDelayScheduledAttempts);
    saturatingIncrement(accepted ? diagnostics.txDelayScheduleAccepted : diagnostics.txDelayScheduleRejected);
    if (!accepted)
        return;

    saturatingIncrement(preSendDiagnostics.txTimerAccepted);
    if (trackedTxTimerActive)
        saturatingIncrement(preSendDiagnostics.txTimerOverwritten);
    trackedTxTimerActive = true;
    trackedTxTimerPacket = packet;
    trackedTxTimerId = packet->id;
    trackedTxTimerDueAtMs = dueAtMs;
    preSendDiagnostics.txTimerActive = true;
    preSendDiagnostics.txTimerDueAtMs = dueAtMs;
}

void W12BenchmarkModule::onTxDelayNotification(bool isTxDelay, const meshtastic_MeshPacket *packet)
{
    if (!trackedTxTimerActive)
        return;

    if (!isTxDelay) {
        saturatingIncrement(preSendDiagnostics.txTimerIrqDisplaced);
    } else if (!packet || packet != trackedTxTimerPacket || packet->id != trackedTxTimerId) {
        saturatingIncrement(preSendDiagnostics.txTimerStale);
    } else {
        saturatingIncrement(preSendDiagnostics.txTimerDispatches);
        const uint32_t nowMs = Time::getMillis();
        if (Throttle::deadlinePassedAt(nowMs, trackedTxTimerDueAtMs) && nowMs != trackedTxTimerDueAtMs) {
            const uint32_t lateMs = nowMs - trackedTxTimerDueAtMs;
            saturatingIncrement(preSendDiagnostics.txTimerLateCount);
            saturatingAdd(preSendDiagnostics.txTimerLateSumMs, lateMs);
            if (lateMs > preSendDiagnostics.txTimerLateMaxMs)
                preSendDiagnostics.txTimerLateMaxMs = lateMs;
        }
    }

    trackedTxTimerActive = false;
    trackedTxTimerPacket = nullptr;
    trackedTxTimerId = 0;
    trackedTxTimerDueAtMs = 0;
    preSendDiagnostics.txTimerActive = false;
    preSendDiagnostics.txTimerDueAtMs = 0;
}

void W12BenchmarkModule::onTxDelayFired(const meshtastic_MeshPacket *packet)
{
    if (collectTxLifecycleDiagnostics() && findTxSlot(packet))
        saturatingIncrement(diagnostics.txDelayFired);
}

void W12BenchmarkModule::onW12BurstArmed(bool startsBurst)
{
    if (collectTxLifecycleDiagnostics()) {
        saturatingIncrement(preSendDiagnostics.burstArmed);
        if (startsBurst)
            saturatingIncrement(preSendDiagnostics.burstCount);
    }
}

void W12BenchmarkModule::onW12BurstFrame()
{
    if (collectTxLifecycleDiagnostics())
        saturatingIncrement(preSendDiagnostics.burstFrames);
}

void W12BenchmarkModule::onW12BurstAborted()
{
    if (collectTxLifecycleDiagnostics())
        saturatingIncrement(preSendDiagnostics.burstAborted);
}

void W12BenchmarkModule::onProducerSendToMeshDuration(uint32_t elapsedUs)
{
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (!collectTxLifecycleDiagnostics())
        return;
    preSendDiagnostics.phaseTiming.available = true;
    recordPhaseTiming(preSendDiagnostics.phaseTiming.producerSendToMeshUs, elapsedUs);
#else
    (void)elapsedUs;
#endif
}

void W12BenchmarkModule::onW12BurstPrepareDuration(uint32_t elapsedUs, bool success)
{
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (!collectTxLifecycleDiagnostics())
        return;
    preSendDiagnostics.phaseTiming.available = true;
    recordPhaseTiming(preSendDiagnostics.phaseTiming.burstPrepareUs, elapsedUs);
    saturatingIncrement(success ? preSendDiagnostics.phaseTiming.burstPrepareSuccesses
                                : preSendDiagnostics.phaseTiming.burstPrepareFailures);
#else
    (void)elapsedUs;
    (void)success;
#endif
}

void W12BenchmarkModule::onW12BurstGuardLateness(uint32_t nowMs, uint32_t dueAtMs)
{
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (!collectTxLifecycleDiagnostics() || nowMs == dueAtMs || !Throttle::deadlinePassedAt(nowMs, dueAtMs))
        return;
    preSendDiagnostics.phaseTiming.available = true;
    recordPhaseTiming(preSendDiagnostics.phaseTiming.burstGuardLateMs, nowMs - dueAtMs);
#else
    (void)nowMs;
    (void)dueAtMs;
#endif
}

void W12BenchmarkModule::onRxGateDecodeDuration(uint32_t elapsedUs)
{
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (!collectDiagnostics())
        return;
    preSendDiagnostics.phaseTiming.available = true;
    recordPhaseTiming(preSendDiagnostics.phaseTiming.rxGateDecodeUs, elapsedUs);
#else
    (void)elapsedUs;
#endif
}

void W12BenchmarkModule::onPkiCcmEncodeTiming(uint32_t count, uint32_t sumUs, uint32_t maxUs)
{
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (!collectTxLifecycleDiagnostics() || count == 0)
        return;
    preSendDiagnostics.phaseTiming.available = true;
    preSendDiagnostics.phaseTiming.pkiCcmAvailable = true;
    recordPhaseTimingAggregate(preSendDiagnostics.phaseTiming.pkiCcmEncodeUs, count, sumUs, maxUs);
#else
    (void)count;
    (void)sumUs;
    (void)maxUs;
#endif
}

void W12BenchmarkModule::onPkiCcmDecodeTiming(uint32_t count, uint32_t sumUs, uint32_t maxUs)
{
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (!collectDiagnostics() || count == 0)
        return;
    preSendDiagnostics.phaseTiming.available = true;
    preSendDiagnostics.phaseTiming.pkiCcmAvailable = true;
    recordPhaseTimingAggregate(preSendDiagnostics.phaseTiming.pkiCcmDecodeUs, count, sumUs, maxUs);
#else
    (void)count;
    (void)sumUs;
    (void)maxUs;
#endif
}

void W12BenchmarkModule::onTxFailureObserved(const meshtastic_MeshPacket *packet, TxFailureStage stage, int16_t radioResult)
{
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    if (!collectTxLifecycleDiagnostics())
        return;
    if (TxSlot *slot = findTxSlot(packet)) {
        slot->failureStage = stage;
        slot->failureRadioResult = radioResult;
    }
#else
    (void)packet;
    (void)stage;
    (void)radioResult;
#endif
}

void W12BenchmarkModule::onPreCanSendDeferred(const meshtastic_MeshPacket *packet)
{
    if (collectTxLifecycleDiagnostics() && findTxSlot(packet))
        saturatingIncrement(diagnostics.preCanSendDeferred);
}

void W12BenchmarkModule::onPreCanSendDeferred(const meshtastic_MeshPacket *packet, PreSendBusyReason reason)
{
    if (!collectTxLifecycleDiagnostics() || !findTxSlot(packet))
        return;

    saturatingIncrement(diagnostics.preCanSendDeferred);
    switch (reason) {
    case PreSendBusyReason::BUSY_TX:
        saturatingIncrement(preSendDiagnostics.busyTxDeferrals);
        break;
    case PreSendBusyReason::BUSY_RX_ACTIVE:
        saturatingIncrement(preSendDiagnostics.busyRxActiveDeferrals);
        break;
    case PreSendBusyReason::BUSY_RX_IRQ_READ_FAILURE:
        saturatingIncrement(preSendDiagnostics.busyRxIrqReadFailureDeferrals);
        break;
    case PreSendBusyReason::UNKNOWN:
        break;
    }
}

void W12BenchmarkModule::onCcaDecision(CcaReason reason)
{
    if (!collectDiagnostics())
        return;
    saturatingIncrement(diagnostics.ccaDecisions);
    const auto index = static_cast<uint8_t>(reason);
    if (index < 7)
        saturatingIncrement(diagnostics.ccaReasons[index]);
}

void W12BenchmarkModule::onCcaRssiSample(int16_t rssiDbm)
{
    if (!collectDiagnostics())
        return;
    saturatingIncrement(diagnostics.ccaRssiSampleCount);
    if (rssiDbm < diagnostics.ccaRssiMinDbm)
        diagnostics.ccaRssiMinDbm = rssiDbm;
    if (rssiDbm > diagnostics.ccaRssiMaxDbm)
        diagnostics.ccaRssiMaxDbm = rssiDbm;
    const uint8_t bin = rssiDbm <= -120   ? 0
                        : rssiDbm <= -110 ? 1
                        : rssiDbm <= -100 ? 2
                        : rssiDbm <= -95  ? 3
                        : rssiDbm <= -90  ? 4
                        : rssiDbm <= -85  ? 5
                        : rssiDbm <= -80  ? 6
                                          : 7;
    saturatingIncrement(diagnostics.ccaRssiHistogram[bin]);
}

void W12BenchmarkModule::onRxIrq(bool readOk, bool rxDone, bool crcError, bool lenError, bool headerCrcError, bool timeout,
                                 bool otherError)
{
    const bool collect = collectDiagnostics();
    const bool collectRadio = collectRadioDiagnostics();
    if (!collect && !collectRadio)
        return;
    if (!readOk) {
        if (collect)
            saturatingIncrement(diagnostics.rxOtherErrors);
        return;
    }
    if (rxDone) {
        if (collect)
            saturatingIncrement(diagnostics.rxIrqDone);
        if (collectRadio) {
            const uint32_t nowMs = Time::getMillis();
            radioDiagnostics.hasLastRxDone = true;
            radioDiagnostics.lastRxDoneAtMs = nowMs;
            if (radioDiagnosticWindowStarted) {
                uint32_t bucket = (nowMs - radioDiagnosticStartMs) / 5000u;
                if (bucket >= 12)
                    bucket = 11;
                saturatingIncrement(radioDiagnostics.rxDoneBy5sBucket[bucket]);
            }
        }
    }
    if (collect && crcError)
        saturatingIncrement(diagnostics.rxCrcErrors);
    if (collect && lenError)
        saturatingIncrement(diagnostics.rxLenErrors);
    if (collect && headerCrcError)
        saturatingIncrement(diagnostics.rxHeaderCrcErrors);
    if (collect && timeout)
        saturatingIncrement(diagnostics.rxTimeouts);
    if (collect && otherError)
        saturatingIncrement(diagnostics.rxOtherErrors);
}

void W12BenchmarkModule::onRxRead(bool success)
{
    if (collectDiagnostics())
        saturatingIncrement(success ? diagnostics.rxReadSuccess : diagnostics.rxReadFailure);
    if (success && collectRadioDiagnostics()) {
        radioDiagnostics.hasLastRxRead = true;
        radioDiagnostics.lastRxReadAtMs = Time::getMillis();
    }
}

void W12BenchmarkModule::onRxQueueEnqueued()
{
    if (collectDiagnostics())
        saturatingIncrement(diagnostics.rxQueueEnqueued);
}

void W12BenchmarkModule::onRxQueueDrop()
{
    if (collectDiagnostics())
        saturatingIncrement(diagnostics.rxQueueDrop);
}

void W12BenchmarkModule::onRxDecode(RxDecodeResult result)
{
    if (!collectDiagnostics())
        return;
    switch (result) {
    case RxDecodeResult::Success:
        saturatingIncrement(diagnostics.rxDecodeSuccess);
        break;
    case RxDecodeResult::Reject:
        saturatingIncrement(diagnostics.rxDecodeReject);
        break;
    case RxDecodeResult::Opaque:
        saturatingIncrement(diagnostics.rxDecodeOpaque);
        break;
    }
}

void W12BenchmarkModule::onRxAuthenticated()
{
    if (collectDiagnostics())
        saturatingIncrement(diagnostics.rxAuthAccepted);
    if (collectRadioDiagnostics()) {
        radioDiagnostics.hasLastRxAuth = true;
        radioDiagnostics.lastRxAuthAtMs = Time::getMillis();
    }
}

void W12BenchmarkModule::onModuleReceiveHandlerDuration(uint32_t elapsedMs)
{
    if (!stats.prepared)
        return;
    saturatingIncrement(diagnostics.moduleReceiveHandlerCount);
    saturatingAdd(diagnostics.moduleReceiveHandlerSumMs, elapsedMs);
    if (elapsedMs > diagnostics.moduleReceiveHandlerMaxMs)
        diagnostics.moduleReceiveHandlerMaxMs = elapsedMs;
}

void W12BenchmarkModule::onRxArmAttempt()
{
    if (!collectRadioDiagnostics())
        return;
    saturatingIncrement(radioDiagnostics.rxArmAttempts);
    radioDiagnostics.rxArmLastStage = static_cast<uint8_t>(RxArmStage::NONE);
}

void W12BenchmarkModule::onRxArmStage(RxArmStage stage, int16_t result, bool retry)
{
    if (!collectRadioDiagnostics())
        return;

    switch (stage) {
    case RxArmStage::STANDBY:
        saturatingIncrement(radioDiagnostics.rxStandbyCalls);
        radioDiagnostics.rxStandbyLastResult = result;
        if (result != RADIOLIB_ERR_NONE)
            saturatingIncrement(radioDiagnostics.rxStandbyFailures);
        break;
    case RxArmStage::RX_START:
        saturatingIncrement(radioDiagnostics.rxStartCalls);
        radioDiagnostics.rxStartLastResult = result;
        if (result != RADIOLIB_ERR_NONE)
            saturatingIncrement(radioDiagnostics.rxStartFailures);
        if (retry)
            saturatingIncrement(radioDiagnostics.rxStartRetryCalls);
        break;
    case RxArmStage::IRQ_MAP:
        saturatingIncrement(radioDiagnostics.rxIrqMapCalls);
        radioDiagnostics.rxIrqMapLastResult = result;
        if (result != RADIOLIB_ERR_NONE)
            saturatingIncrement(radioDiagnostics.rxIrqMapFailures);
        break;
    case RxArmStage::FIFO_CLEAR:
    case RxArmStage::NONE:
        break;
    }
    if (result != RADIOLIB_ERR_NONE)
        radioDiagnostics.rxArmLastStage = static_cast<uint8_t>(stage);
}

void W12BenchmarkModule::onRxArmFinished(int16_t result, RxArmStage failureStage)
{
    if (!collectRadioDiagnostics())
        return;
    radioDiagnostics.rxArmLastResult = result;
    if (result == RADIOLIB_ERR_NONE) {
        saturatingIncrement(radioDiagnostics.rxArmSuccesses);
        radioDiagnostics.rxArmLastStage = static_cast<uint8_t>(RxArmStage::NONE);
    } else {
        saturatingIncrement(radioDiagnostics.rxArmFailures);
        radioDiagnostics.rxArmLastStage = static_cast<uint8_t>(failureStage);
    }
}

void W12BenchmarkModule::onRadioPhase(RadioPhase phase, uint32_t elapsedUs)
{
    if (!collectRadioDiagnostics())
        return;
    uint32_t *count = nullptr;
    uint32_t *sum = nullptr;
    uint32_t *maximum = nullptr;
    switch (phase) {
    case RadioPhase::RX_START:
        count = &radioDiagnostics.rxStartDurationCountUs;
        sum = &radioDiagnostics.rxStartDurationSumUs;
        maximum = &radioDiagnostics.rxStartDurationMaxUs;
        break;
    case RadioPhase::CHANNEL_ACTIVE:
        count = &radioDiagnostics.channelActiveDurationCountUs;
        sum = &radioDiagnostics.channelActiveDurationSumUs;
        maximum = &radioDiagnostics.channelActiveDurationMaxUs;
        break;
    case RadioPhase::START_SEND:
        count = &radioDiagnostics.startSendDurationCountUs;
        sum = &radioDiagnostics.startSendDurationSumUs;
        maximum = &radioDiagnostics.startSendDurationMaxUs;
        break;
    }
    saturatingIncrement(*count);
    saturatingAdd(*sum, elapsedUs);
    if (elapsedUs > *maximum)
        *maximum = elapsedUs;
}

void W12BenchmarkModule::onRadioPoll()
{
    if (collectRadioDiagnostics())
        saturatingIncrement(radioDiagnostics.pollCalls);
}

void W12BenchmarkModule::onRadioPollRx(int16_t result, uint32_t flags, bool pending, uint16_t rawStatus)
{
    if (!collectRadioDiagnostics())
        return;
    saturatingIncrement(radioDiagnostics.pollRxChecks);
    radioDiagnostics.pollRxLastResult = result;
    radioDiagnostics.pollRxLastFlags = flags;
    radioDiagnostics.pollRxFlagsOr |= flags;
    if (result == RADIOLIB_ERR_NONE) {
        saturatingIncrement(radioDiagnostics.pollRxReadSuccess);
        if (pending)
            saturatingIncrement(radioDiagnostics.pollRxPending);
        radioDiagnostics.pollChipStatus0 = static_cast<uint8_t>(rawStatus >> 8);
        radioDiagnostics.pollChipStatus1 = static_cast<uint8_t>(rawStatus);
        radioDiagnostics.pollChipStatusObserved = 1;
        radioDiagnostics.pollChipStatusAtMs = Time::getMillis();
        if ((radioDiagnostics.pollChipStatus1 & 0x07u) == 4u)
            saturatingIncrement(radioDiagnostics.pollChipRxCount);
        else
            saturatingIncrement(radioDiagnostics.pollChipNonRxCount);
    } else {
        saturatingIncrement(radioDiagnostics.pollRxReadFailure);
    }
}

void W12BenchmarkModule::onRadioPollTx(bool pending)
{
    if (!collectRadioDiagnostics())
        return;
    saturatingIncrement(radioDiagnostics.pollTxChecks);
    if (pending)
        saturatingIncrement(radioDiagnostics.pollTxPending);
    radioDiagnostics.pollTxLastDone = pending ? 1 : 0;
}

bool W12BenchmarkModule::collectDiagnostics() const
{
    return stats.prepared && stats.running;
}

bool W12BenchmarkModule::collectTxLifecycleDiagnostics() const
{
    return stats.prepared && (stats.running || pendingTxCount != 0);
}

bool W12BenchmarkModule::collectRadioDiagnostics() const
{
    return stats.prepared && (stats.running || pendingTxCount != 0);
}

bool W12BenchmarkModule::captureRxLiveness()
{
    rxLivenessDiagnostics.snapshotTimeMs = Time::getMillis();
    rxLivenessDiagnostics.sampleStatus = 0;
    rxLivenessDiagnostics.sampleSource = 0;
    rxLivenessDiagnostics.rawIrqFlags = 0;
    rxLivenessDiagnostics.rawStatus = 0;
    rxLivenessDiagnostics.irqReadResult = INT16_MIN;
    rxLivenessDiagnostics.chipRxPackets = 0;
    rxLivenessDiagnostics.chipCrcErrors = 0;
    rxLivenessDiagnostics.chipLenErrors = 0;
    rxLivenessDiagnostics.chipStatsResult = INT16_MIN;
    rxLivenessDiagnostics.rssiDbm = INT16_MIN;
    rxLivenessDiagnostics.rssiReadResult = INT16_MIN;
    rxLivenessDiagnostics.softwareState = 0;

    RadioLibInterface *radio = RadioLibInterface::instance;
    if (!radio)
        return false;

    rxLivenessDiagnostics.softwareState = radio->getW12DiagnosticRadioState();
    W12RxLivenessSample sample;
    if (!radio->readW12RxLiveness(sample))
        return false;

    rxLivenessDiagnostics.sampleSource = 1;
    rxLivenessDiagnostics.sampleStatus |= 32;
    rxLivenessDiagnostics.softwareState = sample.softwareState;
    rxLivenessDiagnostics.rawIrqFlags = sample.rawIrqFlags;
    rxLivenessDiagnostics.rawStatus = sample.rawStatus;
    rxLivenessDiagnostics.irqReadResult = sample.irqReadResult;
    rxLivenessDiagnostics.chipRxPackets = sample.chipRxPackets;
    rxLivenessDiagnostics.chipCrcErrors = sample.chipCrcErrors;
    rxLivenessDiagnostics.chipLenErrors = sample.chipLenErrors;
    rxLivenessDiagnostics.chipStatsResult = sample.chipStatsResult;
    rxLivenessDiagnostics.rssiDbm = sample.rssiDbm;
    rxLivenessDiagnostics.rssiReadResult = sample.rssiReadResult;
    if (sample.irqReadResult == RADIOLIB_ERR_NONE)
        rxLivenessDiagnostics.sampleStatus |= 1;
    if (sample.chipStatsResult == RADIOLIB_ERR_NONE)
        rxLivenessDiagnostics.sampleStatus |= 2;
    if (sample.rssiReadResult == RADIOLIB_ERR_NONE)
        rxLivenessDiagnostics.sampleStatus |= 4;
    return true;
}

bool W12BenchmarkModule::capturePreSendAttribution()
{
    preSendDiagnostics.rxSampleValid = false;
    preSendDiagnostics.rxSampleStatus = 0;
    preSendDiagnostics.rxDioLevel = 0;
    preSendDiagnostics.rxBusyLevel = 0;
    preSendDiagnostics.rxActiveReceiveStartMs = 0;
    preSendDiagnostics.rxSampledAtMs = Time::getMillis();
    preSendDiagnostics.rxRawIrqFlags = 0;
    preSendDiagnostics.rxRawStatus = 0;
    preSendDiagnostics.rxFifoLevel = 0;
    preSendDiagnostics.rxFifoFlags = 0;
    preSendDiagnostics.txFifoFlags = 0;
    preSendDiagnostics.rxChipErrors = 0;
    preSendDiagnostics.rxIrqReadResult = INT16_MIN;
    preSendDiagnostics.rxFifoFlagsResult = INT16_MIN;
    preSendDiagnostics.rxFifoLevelResult = INT16_MIN;
    preSendDiagnostics.rxErrorsResult = INT16_MIN;
    preSendDiagnostics.rxSoftwareState = 0;

    RadioLibInterface *radio = RadioLibInterface::instance;
    if (!radio)
        return false;

    W12RxRecoverySample sample;
    if (!radio->readW12RxRecovery(sample))
        return false;

    preSendDiagnostics.rxSampleValid = true;
    preSendDiagnostics.rxSampleStatus = 16;
    preSendDiagnostics.rxDioLevel = sample.dioLevel;
    preSendDiagnostics.rxBusyLevel = sample.busyLevel;
    preSendDiagnostics.rxActiveReceiveStartMs = sample.activeReceiveStartMs;
    preSendDiagnostics.rxSampledAtMs = sample.sampledAtMs;
    preSendDiagnostics.rxRawIrqFlags = sample.rawIrqFlags;
    preSendDiagnostics.rxRawStatus = sample.rawStatus;
    preSendDiagnostics.rxFifoLevel = sample.rxFifoLevel;
    preSendDiagnostics.rxFifoFlags = sample.fifoRxFlags;
    preSendDiagnostics.txFifoFlags = sample.fifoTxFlags;
    preSendDiagnostics.rxChipErrors = sample.chipErrors;
    preSendDiagnostics.rxIrqReadResult = sample.irqReadResult;
    preSendDiagnostics.rxFifoFlagsResult = sample.fifoFlagsResult;
    preSendDiagnostics.rxFifoLevelResult = sample.fifoLevelResult;
    preSendDiagnostics.rxErrorsResult = sample.errorsResult;
    preSendDiagnostics.rxSoftwareState = sample.softwareState;
    if (sample.irqReadResult == RADIOLIB_ERR_NONE)
        preSendDiagnostics.rxSampleStatus |= 1;
    if (sample.fifoFlagsResult == RADIOLIB_ERR_NONE)
        preSendDiagnostics.rxSampleStatus |= 2;
    if (sample.fifoLevelResult == RADIOLIB_ERR_NONE)
        preSendDiagnostics.rxSampleStatus |= 4;
    if (sample.errorsResult == RADIOLIB_ERR_NONE)
        preSendDiagnostics.rxSampleStatus |= 8;
    return true;
}

bool W12BenchmarkModule::performRxLivenessRearm()
{
    RadioLibInterface *radio = RadioLibInterface::instance;
    if (!radio)
        return false;

    W12RxRearmResult result;
    if (!radio->performW12RxRearm(result))
        return false;

    rxLivenessRearmUsed = true;
    saturatingIncrement(rxLivenessDiagnostics.rearmCount);
    rxLivenessDiagnostics.rearmLastTimeMs = Time::getMillis();
    rxLivenessDiagnostics.rearmLastDurationUs = result.durationUs;
    rxLivenessDiagnostics.rearmBeforeState = static_cast<uint8_t>(result.beforeState);
    rxLivenessDiagnostics.rearmAfterState = static_cast<uint8_t>(result.afterState);
    rxLivenessDiagnostics.rearmResult = static_cast<uint8_t>(result.softwareArmed ? RxLivenessRearmResult::SOFTWARE_ARMED
                                                                                  : RxLivenessRearmResult::SOFTWARE_NOT_ARMED);
    rxLivenessDiagnostics.rearmPerformed = true;
    captureRxLiveness();
    rxLivenessDiagnostics.sampleStatus |= 8;
    if (result.softwareArmed)
        rxLivenessDiagnostics.sampleStatus |= 16;
    return true;
}

void W12BenchmarkModule::producerBlocked(uint32_t &reasonCounter)
{
    if (!collectDiagnostics())
        return;
    saturatingIncrement(diagnostics.producerBlockedTotal);
    saturatingIncrement(reasonCounter);
}

void W12BenchmarkModule::clearBitmap()
{
    memset(receivedBitmap, 0, sizeof(receivedBitmap));
}

bool W12BenchmarkModule::wasReceived(uint32_t sequence) const
{
    return (receivedBitmap[sequence / 8] & (1u << (sequence % 8))) != 0;
}

void W12BenchmarkModule::markReceived(uint32_t sequence)
{
    receivedBitmap[sequence / 8] |= static_cast<uint8_t>(1u << (sequence % 8));
}

void W12BenchmarkModule::resetRun(const RunConfig &config)
{
    activeConfig = config;
    stats = Stats{};
    stats.config = config;
    stats.prepared = true;
    clearBitmap();
    startedAtMs = 0;
    receiverWindowStarted = false;
    snapshotRequested = false;
    snapshotRunMatches = false;
    diagnosticSnapshotRequested = false;
    diagnosticSnapshotRunMatches = false;
    radioDiagnosticSnapshotRequested = false;
    radioDiagnosticSnapshotRunMatches = false;
    radioDiagnosticStartMs = 0;
    radioDiagnosticWindowStarted = false;
    diagnostics = Diagnostics{};
    radioDiagnostics = RadioDiagnostics{};
    rxLivenessDiagnostics = RxLivenessDiagnostics{};
    preSendDiagnostics = PreSendAttributionDiagnostics{};
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    preSendDiagnostics.phaseTiming.available = true;
#endif
    trackedTxTimerPacket = nullptr;
    trackedTxTimerId = 0;
    trackedTxTimerDueAtMs = 0;
    trackedTxTimerActive = false;
    rxLivenessSnapshotRequested = false;
    rxLivenessSnapshotRunMatches = false;
    rxLivenessRearmUsed = false;
    preSendSnapshotRequested = false;
    preSendSnapshotRunMatches = false;
    for (auto &slot : txSlots)
        slot = TxSlot{};
    pendingTxCount = 0;
}

int8_t W12BenchmarkModule::reserveTxSlot(const meshtastic_MeshPacket *packet, uint32_t sequence)
{
    if (!packet || !hasTxCapacity())
        return -1;

    for (uint8_t i = 0; i < TX_SLOT_COUNT; i++) {
        TxSlot &slot = txSlots[i];
        if (!slot.occupied) {
            slot.packet = packet;
            slot.id = packet->id;
            slot.sequence = sequence;
            slot.occupied = true;
            slot.started = false;
            slot.queuedAtMs = Time::getMillis();
            slot.startedAtMs = 0;
            pendingTxCount++;
            return static_cast<int8_t>(i);
        }
    }
    return -1;
}

bool W12BenchmarkModule::hasTxCapacity() const
{
    return pendingTxCount < TX_SLOT_COUNT && pendingTxCount < activeConfig.window;
}

W12BenchmarkModule::TxSlot *W12BenchmarkModule::findTxSlot(const meshtastic_MeshPacket *packet)
{
    if (!packet)
        return nullptr;

    for (auto &slot : txSlots) {
        if (slot.occupied && slot.packet == packet && slot.id == packet->id)
            return &slot;
    }
    return nullptr;
}

void W12BenchmarkModule::finishRun()
{
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
    if (RadioLibInterface::instance)
        RadioLibInterface::instance->abortW12BurstToNormal();
#endif
    if (!stats.running)
        return;

    if (!receiverWindowStarted) {
        // A receiver that saw no authenticated frame has no valid timing window. Preserve the
        // incomplete observation instead of deriving elapsed time from the boot epoch.
        stats.elapsedMs = 0;
        stats.missing = activeConfig.count;
        stats.goodputBps = 0;
        stats.running = false;
        stats.complete = true;
        return;
    }

    uint32_t elapsed = Time::getMillis() - startedAtMs;
    if (elapsed == 0)
        elapsed = 1;
    if (elapsed > activeConfig.durationMs)
        elapsed = activeConfig.durationMs;
    stats.elapsedMs = elapsed;
    stats.missing = activeConfig.count > stats.received ? activeConfig.count - stats.received : 0;
    const uint64_t bytes = static_cast<uint64_t>(stats.received) * activeConfig.size;
    stats.goodputBps = static_cast<uint32_t>((bytes * 1000u) / elapsed);
    stats.running = false;
    stats.complete = true;
}

bool W12BenchmarkModule::handleControl(const meshtastic_MeshPacket &mp)
{
    Op op;
    RunConfig config;
    if (!decodeControl(mp.decoded.payload.bytes, mp.decoded.payload.size, op, config) || !validConfig(config))
        return false;

    if (op == Op::RESET) {
        if (stats.running || pendingTxCount != 0)
            return false;
        resetRun(config);
        return true;
    }

    if (!matchesActiveConfig(config))
        return false;

    switch (op) {
    case Op::START:
        if (stats.running || stats.complete)
            return false;
        stats.running = true;
        radioDiagnosticStartMs = Time::getMillis();
        radioDiagnosticWindowStarted = true;
        receiverWindowStarted = nodeDB->getNodeNum() != activeConfig.destination;
        startedAtMs = receiverWindowStarted ? Time::getMillis() : 0;
        setIntervalFromNow(0);
        return true;
    case Op::STOP:
        finishRun();
        return true;
    case Op::SNAPSHOT:
        if (stats.running && receiverWindowStarted && Throttle::hasElapsed(startedAtMs, activeConfig.durationMs))
            finishRun();
        snapshotRequested = true;
        snapshotRunMatches = true;
        return true;
    case Op::SNAPSHOT_DIAGNOSTICS:
        if (!stats.running && !stats.complete)
            return false;
        if (stats.running && receiverWindowStarted && Throttle::hasElapsed(startedAtMs, activeConfig.durationMs))
            finishRun();
        diagnosticSnapshotRequested = true;
        diagnosticSnapshotRunMatches = true;
        return true;
    case Op::SNAPSHOT_RADIO_DIAGNOSTICS:
        if (!stats.running && !stats.complete)
            return false;
        if (stats.running && receiverWindowStarted && Throttle::hasElapsed(startedAtMs, activeConfig.durationMs))
            finishRun();
        radioDiagnosticSnapshotRequested = true;
        radioDiagnosticSnapshotRunMatches = true;
        return true;
    case Op::SNAPSHOT_RX_LIVENESS:
        if (!stats.running && !stats.complete)
            return false;
        if (stats.running && receiverWindowStarted && Throttle::hasElapsed(startedAtMs, activeConfig.durationMs))
            finishRun();
        captureRxLiveness();
        rxLivenessSnapshotRequested = true;
        rxLivenessSnapshotRunMatches = true;
        return true;
    case Op::REARM_RX_LIVENESS: {
        if (!stats.running || nodeDB->getNodeNum() != activeConfig.destination || !receiverWindowStarted || rxLivenessRearmUsed)
            return false;
        if (Throttle::hasElapsed(startedAtMs, activeConfig.durationMs))
            return false;
        RadioLibInterface *radio = RadioLibInterface::instance;
        if (!radio || radio->isSending() || radio->packetsInTxQueue() != 0)
            return false;
        if (!performRxLivenessRearm())
            return false;
        rxLivenessSnapshotRequested = true;
        rxLivenessSnapshotRunMatches = true;
        return true;
    }
    case Op::SNAPSHOT_PRE_SEND_ATTRIBUTION:
        if (!stats.running && !stats.complete)
            return false;
        if (stats.running && receiverWindowStarted && Throttle::hasElapsed(startedAtMs, activeConfig.durationMs))
            finishRun();
        capturePreSendAttribution();
        preSendSnapshotRequested = true;
        preSendSnapshotRunMatches = true;
        return true;
    case Op::RESET:
        break;
    }
    return false;
}

bool W12BenchmarkModule::handleData(const meshtastic_MeshPacket &mp)
{
    RunConfig frameConfig;
    uint32_t sequence;
    if (!decodeData(mp.decoded.payload.bytes, mp.decoded.payload.size, frameConfig, sequence) ||
        !matchesDataIdentity(frameConfig) || !stats.running ||
        mp.transport_mechanism != meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA || mp.from != activeConfig.source ||
        mp.to != activeConfig.destination || !mp.pki_encrypted || mp.via_mqtt)
        return false;

    if (!receiverWindowStarted) {
        receiverWindowStarted = true;
        startedAtMs = Time::getMillis();
    }

    if (Throttle::hasElapsed(startedAtMs, activeConfig.durationMs)) {
        finishRun();
        return true;
    }

    if (sequence >= activeConfig.count) {
        stats.outOfRange++;
        return true;
    }
    if (wasReceived(sequence)) {
        stats.duplicates++;
        return true;
    }

    bool good = true;
    for (uint16_t i = DATA_HEADER_BYTES; i < activeConfig.size; i++) {
        if (mp.decoded.payload.bytes[i] != patternByte(activeConfig, sequence, i)) {
            good = false;
            break;
        }
    }
    if (good) {
        markReceived(sequence);
        stats.received++;
    } else {
        stats.corrupt++;
    }
    return true;
}

bool W12BenchmarkModule::wantPacket(const meshtastic_MeshPacket *p)
{
    return p && p->which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
           p->decoded.portnum == meshtastic_PortNum_PRIVATE_APP;
}

ProcessMessage W12BenchmarkModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    if (isLocalControl(mp)) {
        ignoreRequest = true;
        const bool recognized = handleControl(mp);
        if (!recognized)
            return ProcessMessage::CONTINUE;
        return ProcessMessage::STOP;
    }

    if (mp.which_payload_variant == meshtastic_MeshPacket_decoded_tag && mp.decoded.portnum == meshtastic_PortNum_PRIVATE_APP &&
        isBenchmarkData(mp)) {
        const bool receiverData =
            stats.running && mp.transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
        const uint32_t handlerStartedAt = receiverData ? Time::getMillis() : 0;
        if (receiverData)
            onRxAuthenticated();
        handleData(mp);
        if (receiverData)
            onModuleReceiveHandlerDuration(Time::getMillis() - handlerStartedAt);
        // RoutingModule still owns forwarding and reliability side effects for RF data.
        return ProcessMessage::CONTINUE;
    }
    return ProcessMessage::CONTINUE;
}

meshtastic_MeshPacket *W12BenchmarkModule::allocReply()
{
    const bool reportRequested = snapshotRequested && snapshotRunMatches;
    const bool diagnosticsRequested = diagnosticSnapshotRequested && diagnosticSnapshotRunMatches;
    const bool radioDiagnosticsRequested = radioDiagnosticSnapshotRequested && radioDiagnosticSnapshotRunMatches;
    const bool rxLivenessRequested = rxLivenessSnapshotRequested && rxLivenessSnapshotRunMatches;
    const bool preSendRequested = preSendSnapshotRequested && preSendSnapshotRunMatches;
    if (!reportRequested && !diagnosticsRequested && !radioDiagnosticsRequested && !rxLivenessRequested && !preSendRequested)
        return nullptr;

    meshtastic_MeshPacket *reply = router->allocForSending();
    if (!reply)
        return nullptr;
    reply->to = nodeDB->getNodeNum();
    reply->hop_limit = 0;
    reply->want_ack = false;
    reply->decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
    const Stats currentStats = getStats();
    if (preSendRequested) {
        reply->decoded.payload.size = encodePreSendAttributionReport(
            reply->decoded.payload.bytes, sizeof(reply->decoded.payload.bytes), currentStats, preSendDiagnostics, pendingTxCount);
    } else if (rxLivenessRequested) {
        saturatingIncrement(rxLivenessDiagnostics.snapshotSequence);
        reply->decoded.payload.size = encodeRxLivenessReport(reply->decoded.payload.bytes, sizeof(reply->decoded.payload.bytes),
                                                             currentStats, rxLivenessDiagnostics, pendingTxCount);
    } else if (radioDiagnosticsRequested) {
        reply->decoded.payload.size = encodeRadioDiagnosticsReport(
            reply->decoded.payload.bytes, sizeof(reply->decoded.payload.bytes), currentStats, radioDiagnostics, pendingTxCount,
            Time::getMillis(), RadioLibInterface::instance ? RadioLibInterface::instance->getW12DiagnosticRadioState() : 0);
    } else if (diagnosticsRequested) {
        reply->decoded.payload.size = encodeDiagnosticsReport(reply->decoded.payload.bytes, sizeof(reply->decoded.payload.bytes),
                                                              currentStats, diagnostics, pendingTxCount);
    } else {
        reply->decoded.payload.size =
            encodeReport(reply->decoded.payload.bytes, sizeof(reply->decoded.payload.bytes), currentStats);
    }
    if (reply->decoded.payload.size == 0) {
        packetPool.release(reply);
        return nullptr;
    }
    snapshotRequested = false;
    snapshotRunMatches = false;
    diagnosticSnapshotRequested = false;
    diagnosticSnapshotRunMatches = false;
    radioDiagnosticSnapshotRequested = false;
    radioDiagnosticSnapshotRunMatches = false;
    rxLivenessSnapshotRequested = false;
    rxLivenessSnapshotRunMatches = false;
    preSendSnapshotRequested = false;
    preSendSnapshotRunMatches = false;
    return reply;
}

W12BenchmarkModule::Stats W12BenchmarkModule::getStats() const
{
    Stats result = stats;
    if (result.prepared) {
        result.missing = result.config.count > result.received ? result.config.count - result.received : 0;
        if (result.running) {
            if (receiverWindowStarted) {
                uint32_t elapsed = Time::getMillis() - startedAtMs;
                if (elapsed == 0)
                    elapsed = 1;
                if (elapsed > result.config.durationMs)
                    elapsed = result.config.durationMs;
                result.elapsedMs = elapsed;
            } else {
                result.elapsedMs = 0;
            }
        }
        if (result.elapsedMs != 0) {
            const uint64_t bytes = static_cast<uint64_t>(result.received) * result.config.size;
            result.goodputBps = static_cast<uint32_t>((bytes * 1000u) / result.elapsedMs);
        } else {
            result.goodputBps = 0;
        }
    }
    return result;
}

int32_t W12BenchmarkModule::runOnce()
{
    if (!stats.running)
        return kIdleIntervalMs;

    if (nodeDB->getNodeNum() != activeConfig.source)
        return kIdleIntervalMs;

    if (Throttle::hasElapsed(startedAtMs, activeConfig.durationMs)) {
        finishRun();
        return kIdleIntervalMs;
    }

    if (stats.enqueued >= activeConfig.count)
        return kIdleIntervalMs;

    const meshtastic_QueueStatus queueStatus = router->getQueueStatus();
    const size_t queueDepth = queueStatus.maxlen >= queueStatus.free ? queueStatus.maxlen - queueStatus.free : queueStatus.maxlen;
    if (queueStatus.free == 0) {
        producerBlocked(diagnostics.producerQueueFreeZero);
        return kQueueRetryIntervalMs;
    }
    if (queueDepth >= activeConfig.window) {
        producerBlocked(diagnostics.producerQueueWindow);
        return kQueueRetryIntervalMs;
    }
    if (!hasTxCapacity()) {
        producerBlocked(diagnostics.producerTxCapacity);
        return kQueueRetryIntervalMs;
    }

    meshtastic_MeshPacket *packet = router->allocForSending();
    if (!packet) {
        stats.sendFailures++;
        return kQueueRetryIntervalMs;
    }
    packet->to = activeConfig.destination;
    packet->hop_limit = 0;
    packet->want_ack = false;
    packet->pki_encrypted = true;
    packet->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    packet->decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
    packet->decoded.payload.size =
        encodeData(packet->decoded.payload.bytes, sizeof(packet->decoded.payload.bytes), activeConfig, stats.enqueued);
    if (packet->decoded.payload.size == 0) {
        packetPool.release(packet);
        stats.sendFailures++;
        return kQueueRetryIntervalMs;
    }

    const int8_t slotIndex = reserveTxSlot(packet, stats.enqueued);
    if (slotIndex < 0) {
        packetPool.release(packet);
        producerBlocked(diagnostics.producerTxCapacity);
        return kQueueRetryIntervalMs;
    }

    // Start after allocation, payload construction, and owner-slot reservation. This isolates the
    // producer's complete service admission call, including any synchronous work below it.
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    const uint32_t producerStartedAtUs = micros();
    const ErrorCode result = service->sendToMesh(packet, RX_SRC_LOCAL, false);
    onProducerSendToMeshDuration(static_cast<uint32_t>(micros() - producerStartedAtUs));
#else
    const ErrorCode result = service->sendToMesh(packet, RX_SRC_LOCAL, false);
#endif
    if (result == ERRNO_OK)
        stats.enqueued++;
    else {
        // Router admission can fail before the radio lifecycle hook runs. The packet may already
        // have been released, so clear the slot by index and never dereference the packet here.
        if (txSlots[slotIndex].occupied) {
            txSlots[slotIndex] = TxSlot{};
            if (pendingTxCount != 0)
                pendingTxCount--;
        }
        stats.sendFailures++;
    }
    return kProducerIntervalMs;
}

#endif
