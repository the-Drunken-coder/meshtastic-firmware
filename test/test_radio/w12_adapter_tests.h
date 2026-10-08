#pragma once

// LR2021Interface in src/mesh/LR2021Interface.cpp must restore FLRC after a radio fault,
// reject terminal RX errors before reading payloads, and count TX only after TX_DONE.
// These checks use the production adapter and pinned RadioLib driver with scripted SPI,
// guarding against adapter recovery falling into LoRa and failed sends crediting success.
// The shared TX-delay path must defer a busy passive observation without interrupting RX
// or clearing RX_DONE before its queued notification delivers the received frame once.
#if ARCH_PORTDUINO && RADIOLIB_EXCLUDE_LR2021 != 1

#include "../test_radiolib_drivers/RecordingHal.h"
#include "LR2021Interface.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "PowerMon.h"
#include "RadioTxHook.h"
#include "Router.h"
#include "UptimeClock.h"
#include "airtime.h"
#include "modules/W12BenchmarkModule.h"

#include <cstring>
#include <memory>
#include <vector>

class W12AdapterHal : public LockingArduinoHal
{
  public:
    W12AdapterHal() : LockingArduinoHal(SPI, SPISettings(4000000, MSBFIRST, SPI_MODE0))
    {
        recording.reply(op16(RADIOLIB_LR2021_CMD_GET_VERSION), 0x04, {0x04, 0x04, 0x01, 0x18}, true);
        recording.reply(op16(RADIOLIB_LR2021_CMD_GET_PACKET_TYPE), 0x04, {0x04, 0x04, RADIOLIB_LR2021_PACKET_TYPE_FLRC}, true);
    }

    RecordingHal recording;
    uint32_t irq = 0;
    uint16_t failCommand = 0;
    uint16_t failCommandOccurrence = 0;
    unsigned failCommandSeen = 0;
    bool packetTypeOverrideEnabled = false;
    uint8_t packetTypeOverride = RADIOLIB_LR2021_PACKET_TYPE_NONE;
    uint16_t rxPacketLengthOverride = 0;
    uint16_t rxPacketLengthOverrideOccurrence = 0;
    unsigned rxPacketLengthReads = 0;
    uint16_t rssiHalfDbm = 220;
    unsigned interruptsArmed = 0;
    unsigned interruptsDisarmed = 0;
    uint32_t irqOnSetTx = 0;
    bool interruptArmed = false;
    bool interruptArmedAtSetTx = false;
    bool rawStatusFailed = false;
    uint8_t rawStatusMode = 0x04;
    uint16_t rxStatsPackets = 12;
    uint16_t rxStatsCrcErrors = 3;
    uint16_t rxStatsLenErrors = 2;
    uint8_t fifoRxFlags = 0x12;
    uint8_t fifoTxFlags = 0x34;
    uint16_t rxFifoLevel = 0x4567;
    uint16_t chipErrors = 0x89AB;
    // Keep the fixture's default pins idle so production init sees BUSY low. Diagnostic tests
    // set asserted levels explicitly when sampling the on-demand RX page.
    uint32_t busyLevel = 0;
    uint32_t dioLevel = 0;
    unsigned rssiReads = 0;
    unsigned injectIrqAtRssiRead = 0;
    uint32_t irqOnRssiRead = 0;
    unsigned irqReads = 0;
    unsigned injectIrqAtRead = 0;
    uint32_t irqOnRead = 0;
    unsigned rawStatusReads = 0;
    unsigned failRawStatusOccurrence = 0;
    // Atomic FLRC consume draft controls. These exercise reply bytes in both
    // command and NOP phases while preserving this fixture's existing tests.
    bool atomicConsumeEnabled = false;
    bool atomicTimeoutSnapshotCommand = false;
    bool atomicFailSnapshotReply = false;
    bool atomicFailPacketStatusReply = false;
    bool atomicFailFifoReply = false;
    bool atomicFailPacketTypeReply = false;
    unsigned atomicPacketTypeFailOccurrence = 0;
    unsigned atomicPacketTypeReads = 0;
    unsigned atomicSnapshotCommandTimeouts = 0;
    uint8_t atomicStatusMode = 0x01;
    uint32_t atomicIrq = RADIOLIB_LR2021_IRQ_RX_DONE;
    uint16_t atomicPacketLength = 0;
    uint8_t atomicRssiAverageRaw = 0x50;
    uint8_t atomicRssiSyncRaw = 0x30;
    uint8_t atomicSyncWord = 0x10;
    std::vector<uint8_t> atomicPayload;

    void signalReceive(uint32_t flags)
    {
        irq = flags;
        if ((flags & W12FlrcProfile::RECEIVE_IRQS) && interruptCallback)
            interruptCallback();
    }

    void pinMode(uint32_t, uint32_t) override {}
    void digitalWrite(uint32_t, uint32_t) override {}
    uint32_t digitalRead(uint32_t pin) override { return pin == 2 ? busyLevel : dioLevel; }
    void attachInterrupt(uint32_t, void (*callback)(void), uint32_t) override
    {
        interruptsArmed++;
        interruptArmed = true;
        interruptCallback = callback;
    }
    void detachInterrupt(uint32_t) override
    {
        interruptsDisarmed++;
        interruptArmed = false;
        interruptCallback = nullptr;
    }
    void delay(RadioLibTime_t ms) override { recording.delay(ms); }
    void delayMicroseconds(RadioLibTime_t us) override { recording.delayMicroseconds(us); }
    RadioLibTime_t millis() override { return recording.millis(); }
    RadioLibTime_t micros() override { return recording.micros(); }
    long pulseIn(uint32_t, uint32_t, RadioLibTime_t) override { return 0; }
    void spiBegin() override {}
    void spiEnd() override {}
    void spiBeginTransaction() override {}
    void spiEndTransaction() override {}

    void spiTransfer(uint8_t *out, size_t length, uint8_t *in) override
    {
        recording.spiTransfer(out, length, in);
        if (atomicIrqReplyPending) {
            atomicIrqReplyPending = false;
            in[0] = atomicSnapshotReplyFailed ? 0x02 : 0x04;
            in[1] = atomicStatusMode;
            in[2] = static_cast<uint8_t>(atomicIrq >> 24);
            in[3] = static_cast<uint8_t>(atomicIrq >> 16);
            in[4] = static_cast<uint8_t>(atomicIrq >> 8);
            in[5] = static_cast<uint8_t>(atomicIrq);
            return;
        }
        if (atomicPacketStatusReplyPending) {
            atomicPacketStatusReplyPending = false;
            in[0] = atomicFailPacketStatusReply ? 0x02 : 0x04;
            in[1] = atomicStatusMode;
            in[2] = static_cast<uint8_t>(atomicPacketLength >> 8);
            in[3] = static_cast<uint8_t>(atomicPacketLength);
            in[4] = atomicRssiAverageRaw;
            in[5] = atomicRssiSyncRaw;
            in[6] = atomicSyncWord;
            return;
        }
        if (packetTypeReplyPending) {
            packetTypeReplyPending = false;
            if (atomicPacketTypeReplyFailed)
                in[0] = 0x02;
            if (packetTypeOverrideEnabled)
                in[2] = packetTypeOverride;
            return;
        }
        if (rxPacketLengthReplyPending) {
            rxPacketLengthReplyPending = false;
            if (rxPacketLengthReplyFailed) {
                in[0] = 0x02;
                in[2] = 0;
                in[3] = 0;
            } else if (rxPacketLengthReplyOverride) {
                in[2] = static_cast<uint8_t>(rxPacketLengthOverride >> 8);
                in[3] = static_cast<uint8_t>(rxPacketLengthOverride);
            }
            return;
        }
        if (rxStatsReplyPending) {
            rxStatsReplyPending = false;
            in[0] = rxStatsReplyFailed ? 0x02 : 0x04;
            in[1] = 0x04;
            in[2] = rxStatsPackets >> 8;
            in[3] = rxStatsPackets;
            in[4] = rxStatsCrcErrors >> 8;
            in[5] = rxStatsCrcErrors;
            in[6] = rxStatsLenErrors >> 8;
            in[7] = rxStatsLenErrors;
            return;
        }
        if (rssiReplyPending) {
            rssiReplyPending = false;
            if (++rssiReads == injectIrqAtRssiRead)
                signalReceive(irqOnRssiRead);
            in[0] = rssiReplyFailed ? 0x02 : 0x04;
            in[1] = 0x04;
            in[2] = rssiHalfDbm >> 1;
            in[3] = (rssiHalfDbm & 1) << 7;
            return;
        }
        if (fifoFlagsReplyPending) {
            fifoFlagsReplyPending = false;
            in[0] = fifoFlagsReplyFailed ? 0x02 : 0x04;
            in[1] = 0x04;
            in[2] = fifoRxFlags;
            in[3] = fifoTxFlags;
            return;
        }
        if (fifoLevelReplyPending) {
            fifoLevelReplyPending = false;
            in[0] = fifoLevelReplyFailed ? 0x02 : 0x04;
            in[1] = 0x04;
            in[2] = rxFifoLevel >> 8;
            in[3] = rxFifoLevel;
            return;
        }
        if (errorsReplyPending) {
            errorsReplyPending = false;
            in[0] = errorsReplyFailed ? 0x02 : 0x04;
            in[1] = 0x04;
            in[2] = chipErrors >> 8;
            in[3] = chipErrors;
            return;
        }
        if (length >= 2) {
            uint16_t command = (uint16_t(out[0]) << 8) | out[1];
            const bool commandFailed = failCommand && command == failCommand &&
                                       (failCommandOccurrence == 0 || ++failCommandSeen == failCommandOccurrence);
            if (command == RADIOLIB_LR2021_CMD_GET_FLRC_RX_STATS) {
                rxStatsReplyPending = true;
                rxStatsReplyFailed = commandFailed;
            }
            if (command == RADIOLIB_LR2021_CMD_GET_RSSI_INST) {
                rssiReplyPending = true;
                rssiReplyFailed = commandFailed;
            }
            if (command == RADIOLIB_LR2021_CMD_GET_FIFO_IRQ_FLAGS) {
                fifoFlagsReplyPending = true;
                fifoFlagsReplyFailed = commandFailed;
            }
            if (command == RADIOLIB_LR2021_CMD_GET_RX_FIFO_LEVEL) {
                fifoLevelReplyPending = true;
                fifoLevelReplyFailed = commandFailed;
            }
            if (command == RADIOLIB_LR2021_CMD_GET_ERRORS) {
                errorsReplyPending = true;
                errorsReplyFailed = commandFailed;
            }
            if (command == RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH) {
                const unsigned occurrence = ++rxPacketLengthReads;
                // LRxxxx checks the separate reply, not this zero-payload command transaction.
                rxPacketLengthReplyPending = true;
                rxPacketLengthReplyFailed = commandFailed;
                rxPacketLengthReplyOverride =
                    rxPacketLengthOverrideOccurrence != 0 && occurrence == rxPacketLengthOverrideOccurrence;
            }
            if (command == RADIOLIB_LR2021_CMD_GET_PACKET_TYPE) {
                if (atomicConsumeEnabled) {
                    const unsigned occurrence = ++atomicPacketTypeReads;
                    atomicPacketTypeReplyFailed = atomicFailPacketTypeReply && atomicPacketTypeFailOccurrence != 0 &&
                                                  occurrence == atomicPacketTypeFailOccurrence;
                } else {
                    atomicPacketTypeReplyFailed = commandFailed;
                }
                // SPIcommand always follows the command phase with a NOP;
                // carry a command-status fault into that reply.
                atomicPacketTypeReplyFailed = atomicPacketTypeReplyFailed || commandFailed;
                packetTypeReplyPending = true;
            }
            if (atomicConsumeEnabled && command == RADIOLIB_LR2021_CMD_GET_AND_CLEAR_IRQ_STATUS) {
                // The command uses verify=false, so its Stat byte is observed
                // only by the following NOP phase.
                atomicIrqReplyPending = true;
                atomicSnapshotReplyFailed = atomicTimeoutSnapshotCommand || atomicFailSnapshotReply || commandFailed;
                if (atomicTimeoutSnapshotCommand) {
                    ++atomicSnapshotCommandTimeouts;
                    busyLevel = 1; // Exercise Module's actual post-command BUSY timeout.
                    // An aborted command never reaches SPIcommand's NOP reply.
                    // Its recovery standby transaction has a different size.
                    atomicIrqReplyPending = false;
                }
            }
            if (atomicConsumeEnabled && command == RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS) {
                atomicPacketStatusReplyPending = true;
                atomicFailPacketStatusReply = atomicFailPacketStatusReply || commandFailed;
            }
            if (atomicConsumeEnabled && command == RADIOLIB_LR2021_CMD_READ_RX_FIFO) {
                // READ_RX_FIFO is one transaction. With status width zero,
                // Module copies buffIn[2..] to the payload after parsing
                // Stat1=buffIn[0] and Stat2=buffIn[1].
                const bool fifoFailed = atomicFailFifoReply || commandFailed;
                in[0] = fifoFailed ? 0x02 : 0x04;
                in[1] = atomicStatusMode;
                for (size_t i = 0; i < atomicPayload.size() && i + 2 < length; ++i)
                    in[i + 2] = atomicPayload[i];
            }
            if (command == RADIOLIB_LR2021_CMD_CLEAR_IRQ && length >= 6) {
                uint32_t mask = (uint32_t(out[2]) << 24) | (uint32_t(out[3]) << 16) | (uint32_t(out[4]) << 8) | out[5];
                irq &= ~mask;
            }
            if (command == RADIOLIB_LR2021_CMD_SET_TX) {
                interruptArmedAtSetTx = interruptArmed;
                // Complete during the actual command; firmware must observe the IRQ after startTransmit returns.
                irq = irqOnSetTx;
            }
            // Zero-payload writes are verified by RadioLib with a following six-byte NOP status
            // read, so carry a scripted CLEAR_RX_FIFO failure into that status transaction.
            if (command == RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO && commandFailed)
                clearRxFifoStatusFailed = true;
            if (commandFailed)
                in[0] = 0x02;
        }
        if (length == 6 && std::all_of(out, out + length, [](uint8_t b) { return b == 0; })) {
            if (++irqReads == injectIrqAtRead)
                signalReceive(irqOnRead);
            const unsigned rawStatusOccurrence = ++rawStatusReads;
            const bool failThisRawStatus = rawStatusFailed || clearRxFifoStatusFailed ||
                                           (failRawStatusOccurrence != 0 && rawStatusOccurrence == failRawStatusOccurrence);
            in[0] = failThisRawStatus ? 0x02 : 0x04;
            in[1] = rawStatusMode;
            in[2] = irq >> 24;
            in[3] = irq >> 16;
            in[4] = irq >> 8;
            in[5] = irq;
            clearRxFifoStatusFailed = false;
        }
    }

  private:
    bool rxStatsReplyPending = false;
    bool rxStatsReplyFailed = false;
    bool rssiReplyPending = false;
    bool rssiReplyFailed = false;
    bool fifoFlagsReplyPending = false;
    bool fifoFlagsReplyFailed = false;
    bool fifoLevelReplyPending = false;
    bool fifoLevelReplyFailed = false;
    bool errorsReplyPending = false;
    bool errorsReplyFailed = false;
    bool clearRxFifoStatusFailed = false;
    bool atomicIrqReplyPending = false;
    bool atomicSnapshotReplyFailed = false;
    bool atomicPacketStatusReplyPending = false;
    bool atomicPacketTypeReplyFailed = false;
    bool packetTypeReplyPending = false;
    bool rxPacketLengthReplyPending = false;
    bool rxPacketLengthReplyFailed = false;
    bool rxPacketLengthReplyOverride = false;
    void (*interruptCallback)() = nullptr;
};

class TestableW12Adapter : public LR2021Interface
{
  public:
    explicit TestableW12Adapter(W12AdapterHal *hal) : LR2021Interface(hal, 1, 3, 4, 2) {}
    void armReceive() { startReceive(); }
    bool recover() { return recoverChipStateLoss(); }
    void stop() { setStandby(); }
    void stopViaLoRaBase() { LR20x0Interface::setStandby(); }
    bool channelActive() { return isChannelActive(); }
    bool receiveActive() { return isActivelyReceiving(); }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    W12ActiveReceiveState activeReceiveState() { return readW12ActiveReceiveState(); }
    bool readRecovery(W12RxRecoverySample &sample) { return readW12RxRecovery(sample); }
#endif
    bool isOffline() const { return rxOffline; }
    bool receiving() const { return isReceiving; }
    // The macro-enabled production seam is opted into per new test. Keeping
    // this fixture switch false preserves the existing generic receive tests
    // when the atomic macro is enabled for the suite.
    bool atomicConsumeForTest = false;
    bool forceGenericReceive = false;
    bool consumeReceivePacket(uint8_t *data, size_t capacity, RadioReceiveConsumeResult &result) override
    {
        if (forceGenericReceive || !atomicConsumeForTest) {
            result = RadioReceiveConsumeResult{};
            return false;
        }
        return LR2021Interface::consumeReceivePacket(data, capacity, result);
    }
    bool reconfigureForTest() { return reconfigure(); }
    uint32_t badReceives() const { return rxBad; }
    uint32_t goodTransmits() const { return txGood; }
    uint16_t droppedTransmits() const { return txDrop; }
    int16_t changeCrc(uint8_t bytes) { return lora.setCRC(bytes); }
    int16_t configureImplicitRxForTest(uint8_t len) { return lora.implicitHeader(len); }
    int16_t configureExplicitRxForTest() { return lora.explicitHeader(); }
    size_t driverPacketLengthForTest() { return lora.getPacketLength(); }
    int16_t readDriverForTest(uint8_t *data, size_t len) { return lora.readData(data, len); }
    uint32_t driverDuration(size_t bytes) { return lora.getTimeOnAir(bytes); }
    void receiveInterrupt() { handleReceiveInterrupt(); }
    void transmitInterrupt() { handleTransmitInterrupt(); }
    size_t takeTransmission(meshtastic_MeshPacket *packet) { return beginSending(packet); }
    bool sendNow(meshtastic_MeshPacket *packet) { return startSend(packet); }
    void serviceNotifications() { checkNotification(); }
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
    static constexpr uint32_t burstGuardMsForTest() { return W12_BURST_GUARD_MS; }
    bool queueBurstNotificationForTest(uint32_t delay = burstGuardMsForTest())
    {
        return notifyLater(delay, W12_BURST_DELAY_COMPLETED, false);
    }
    bool queueOrdinaryNotificationForTest() { return notify(TRANSMIT_DELAY_COMPLETED, false); }
    bool queueTxNotificationForTest() { return notify(ISR_TX, true); }
    bool queueOnlyForTest(meshtastic_MeshPacket *packet)
    {
        bool dropped = false;
        return txQueue.enqueue(packet, &dropped) && !dropped;
    }
    void armOrdinaryTimerForTest() { setTransmitDelay(); }
    bool burstTimerPendingForTest() const { return w12Burst.timerPending; }
    bool notifyForTest(uint32_t notification, bool overwrite) { return notify(notification, overwrite); }
    meshtastic_MeshPacket *frontForTest() { return txQueue.getFront(); }
    meshtastic_MeshPacket *sendingForTest() const { return sendingPacket; }
#endif
    bool queueTransmission(meshtastic_MeshPacket *packet)
    {
        bool dropped = false;
        if (!txQueue.enqueue(packet, &dropped))
            return false;
        return notify(TRANSMIT_DELAY_COMPLETED, true);
    }
    void releaseQueuedTransmissions()
    {
        while (auto *packet = txQueue.dequeue()) {
            notifyTxFinished(packet, TxState::Cancelled);
            packetPool.release(packet);
        }
    }
};

#if W12_BENCHMARK_HAL_TIMING_ENABLED
class W12ProductionHalAdapter : public LR2021Interface
{
  public:
    W12ProductionHalAdapter() : LR2021Interface(&productionHal(), 1, 3, 4, 2) {}

    void exerciseProductionHal()
    {
        RadioLibHal *radioLibHal = hal;
        TEST_ASSERT_NOT_NULL(radioLibHal);
        uint8_t out[64] = {};
        uint8_t in[64] = {};
        radioLibHal->spiBeginTransaction();
        radioLibHal->spiTransfer(out, sizeof(out), in);
        radioLibHal->yield();
        radioLibHal->spiEndTransaction();
    }

    static void exerciseAttachedHal()
    {
        RadioLibHal *radioLibHal = &productionHal();
        uint8_t out[64] = {};
        uint8_t in[64] = {};
        radioLibHal->spiBeginTransaction();
        radioLibHal->spiTransfer(out, sizeof(out), in);
        radioLibHal->yield();
        radioLibHal->spiEndTransaction();
    }

  private:
    static SPIClass &localSpi()
    {
        static SPIClass spi;
        return spi;
    }

    static LockingArduinoHal &productionHal()
    {
        static LockingArduinoHal hal(localSpi(), SPISettings(4000000, MSBFIRST, SPI_MODE0));
        static const bool initialized = [] {
            auto &spi = localSpi();
            spi.end();
            spi.begin("/dev/w12-hal-timing-device-does-not-exist");
            return true;
        }();
        (void)initialized;
        return hal;
    }
};

class W12BenchmarkHalMetricsTestAccess
{
  public:
    static void recordTransfer(W12BenchmarkHalMetrics &metrics, uint32_t durationUs, size_t logicalBytes)
    {
        metrics.recordTransfer(durationUs, logicalBytes);
    }

    static void recordYield(W12BenchmarkHalMetrics &metrics, uint32_t durationUs) { metrics.recordYield(durationUs); }

    static W12BenchmarkHalMetrics::Snapshot &snapshot(W12BenchmarkHalMetrics &metrics) { return metrics.snapshot; }
};

static void test_w12_hal_metrics_saturate_and_preserve_zero_duration()
{
    W12BenchmarkHalMetrics metrics;
    metrics.begin();
    W12BenchmarkHalMetricsTestAccess::recordTransfer(metrics, 0, 64);
    W12BenchmarkHalMetricsTestAccess::recordYield(metrics, 0);
    auto snapshot = metrics.get();
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(64, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT64(0, snapshot.transferSumUs);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.transferMaxUs);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.yieldCount);
    TEST_ASSERT_EQUAL_UINT64(0, snapshot.yieldSumUs);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.yieldMaxUs);

    auto &mutableSnapshot = W12BenchmarkHalMetricsTestAccess::snapshot(metrics);
    mutableSnapshot.transferCount = UINT32_MAX;
    mutableSnapshot.transferredBytes = UINT64_MAX;
    mutableSnapshot.transferSumUs = UINT64_MAX;
    mutableSnapshot.yieldCount = UINT32_MAX;
    mutableSnapshot.yieldSumUs = UINT64_MAX;
    W12BenchmarkHalMetricsTestAccess::recordTransfer(metrics, 7, 1);
    W12BenchmarkHalMetricsTestAccess::recordYield(metrics, 9);
    snapshot = metrics.get();
    TEST_ASSERT_TRUE(snapshot.overflow);
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, snapshot.transferSumUs);
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, snapshot.yieldCount);
    TEST_ASSERT_EQUAL_UINT64(UINT64_MAX, snapshot.yieldSumUs);
    TEST_ASSERT_EQUAL_UINT32(7, snapshot.transferMaxUs);
    TEST_ASSERT_EQUAL_UINT32(9, snapshot.yieldMaxUs);

    metrics.freeze();
    TEST_ASSERT_TRUE(metrics.get().frozen);
}

static void test_w12_production_hal_virtual_transfer_and_yield_are_counted()
{
    auto *production = new W12ProductionHalAdapter();
    production->exerciseProductionHal();
    auto snapshot = production->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(4000000, snapshot.requestedHz);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(0, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.yieldCount);
    TEST_ASSERT_FALSE(snapshot.frozen);

    production->beginW12HalTiming();
    production->exerciseProductionHal();
    production->freezeW12HalTiming();
    snapshot = production->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(4000000, snapshot.requestedHz);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(64, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.yieldCount);
    TEST_ASSERT_TRUE(snapshot.transferMaxUs <= snapshot.transferSumUs);
    TEST_ASSERT_TRUE(snapshot.yieldMaxUs <= snapshot.yieldSumUs);
    TEST_ASSERT_TRUE(snapshot.frozen);

    // A frozen collector ignores later virtual HAL activity and keeps the completed snapshot.
    const auto frozen = snapshot;
    production->exerciseProductionHal();
    snapshot = production->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(frozen.transferCount, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(frozen.transferredBytes, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT64(frozen.transferSumUs, snapshot.transferSumUs);
    TEST_ASSERT_EQUAL_UINT32(frozen.transferMaxUs, snapshot.transferMaxUs);
    TEST_ASSERT_EQUAL_UINT32(frozen.yieldCount, snapshot.yieldCount);
    TEST_ASSERT_EQUAL_UINT64(frozen.yieldSumUs, snapshot.yieldSumUs);
    TEST_ASSERT_EQUAL_UINT32(frozen.yieldMaxUs, snapshot.yieldMaxUs);
    TEST_ASSERT_TRUE(snapshot.frozen);

    // RESET makes the next interval inactive until a fresh logical START arms it.
    production->resetW12HalTiming();
    production->exerciseProductionHal();
    snapshot = production->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(4000000, snapshot.requestedHz);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(0, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT64(0, snapshot.transferSumUs);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.transferMaxUs);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.yieldCount);
    TEST_ASSERT_EQUAL_UINT64(0, snapshot.yieldSumUs);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.yieldMaxUs);
    TEST_ASSERT_FALSE(snapshot.frozen);

    production->beginW12HalTiming();
    production->exerciseProductionHal();
    production->freezeW12HalTiming();
    snapshot = production->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(64, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.yieldCount);
    TEST_ASSERT_TRUE(snapshot.frozen);
    delete production;
}

static void test_w12_production_hal_detach_and_reattach_does_not_use_freed_metrics()
{
    auto *first = new W12ProductionHalAdapter();
    first->beginW12HalTiming();
    first->exerciseProductionHal();
    delete first;

    // The HAL outlives the interface in production. After destruction, its non-owning metrics
    // pointer must be detached before this virtual transfer/yield pair runs.
    W12ProductionHalAdapter::exerciseAttachedHal();

    auto *second = new W12ProductionHalAdapter();
    second->beginW12HalTiming();
    second->exerciseProductionHal();
    second->freezeW12HalTiming();
    const auto snapshot = second->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(64, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.yieldCount);
    TEST_ASSERT_TRUE(snapshot.frozen);
    delete second;
    W12ProductionHalAdapter::exerciseAttachedHal();
}
#endif

static W12AdapterHal *adapterHal;
static TestableW12Adapter *adapter;
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
// Unity assertions longjmp out of a test, so stack-registered RadioTxHooks can
// outlive their object. Keep test hooks fixture-owned and unregister them before
// releasing the adapter or any queued packets.
static RadioTxHook *adapterOwnedTxHook;
#endif
static void makeW12Adapter();

#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
// The production four-frame case temporarily lets Router own the real adapter,
// so MeshService admission reserves the same W12 owner slots that the radio
// gate checks. The ordinary adapter tests keep their original ownership path.
static Router *adapterBurstOwnedRouter;
static MeshService *adapterBurstOwnedService;
class AdapterBurstNodeDB;
static AdapterBurstNodeDB *adapterBurstOwnedNodeDB;
static Router *adapterBurstSavedRouter;
static MeshService *adapterBurstSavedService;
static NodeDB *adapterBurstSavedNodeDB;
static meshtastic_MyNodeInfo adapterBurstSavedNodeInfo;
#endif

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
#if defined(MESHTASTIC_W12_BENCHMARK_SINGLE_RX) && MESHTASTIC_W12_BENCHMARK_SINGLE_RX
static constexpr uint8_t adapterExpectedRxTimeout[3] = {0, 0, 0};
#elif defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS)
static constexpr uint8_t adapterExpectedRxTimeout[3] = {
    static_cast<uint8_t>(W12FlrcProfile::RX_TIMEOUT_TICKS >> 16),
    static_cast<uint8_t>(W12FlrcProfile::RX_TIMEOUT_TICKS >> 8),
    static_cast<uint8_t>(W12FlrcProfile::RX_TIMEOUT_TICKS),
};
#else
static constexpr uint8_t adapterExpectedRxTimeout[3] = {0xFF, 0xFF, 0xFF};
#endif
#else
static constexpr uint8_t adapterExpectedRxTimeout[3] = {0xFF, 0xFF, 0xFF};
#endif

static void assertAdapterSetRxTimeout()
{
    const auto *setRx = adapterHal->recording.last(op16(RADIOLIB_LR2021_CMD_SET_RX));
    TEST_ASSERT_NOT_NULL(setRx);
    TEST_ASSERT_GREATER_OR_EQUAL_size_t(5, setRx->size());
    TEST_ASSERT_EQUAL_UINT8(adapterExpectedRxTimeout[0], (*setRx)[2]);
    TEST_ASSERT_EQUAL_UINT8(adapterExpectedRxTimeout[1], (*setRx)[3]);
    TEST_ASSERT_EQUAL_UINT8(adapterExpectedRxTimeout[2], (*setRx)[4]);
#if defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS) && MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS == 1000
    TEST_ASSERT_EQUAL_UINT8(0x00, (*setRx)[2]);
    TEST_ASSERT_EQUAL_UINT8(0x80, (*setRx)[3]);
    TEST_ASSERT_EQUAL_UINT8(0x00, (*setRx)[4]);
#endif
}

static size_t adapterTransactionIndex(const std::vector<uint8_t> &prefix, size_t occurrence)
{
    size_t seen = 0;
    for (size_t index = 0; index < adapterHal->recording.transactions.size(); ++index) {
        const auto &transaction = adapterHal->recording.transactions[index];
        if (transaction.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), transaction.begin()) &&
            ++seen == occurrence)
            return index;
    }
    return adapterHal->recording.transactions.size();
}

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
class TestableW12AdapterDiagnostics : public W12BenchmarkModule
{
  public:
    using W12BenchmarkModule::allocReply;
    using W12BenchmarkModule::handleReceived;
    using W12BenchmarkModule::runOnce;
};
static TestableW12AdapterDiagnostics *adapterDiagnostics;

#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
class AdapterBurstNodeDB : public NodeDB
{
  public:
    void clearTestNodes()
    {
        testNodes.clear();
        meshNodes = &testNodes;
        numMeshNodes = 0;
    }

    void addPublicKey(NodeNum num, const uint8_t *key)
    {
        meshtastic_NodeInfoLite node = meshtastic_NodeInfoLite_init_zero;
        node.num = num;
        node.public_key.size = 32;
        memcpy(node.public_key.bytes, key, 32);
        testNodes.push_back(node);
        meshNodes = &testNodes;
        numMeshNodes = testNodes.size();
    }

  private:
    std::vector<meshtastic_NodeInfoLite> testNodes;
};

static constexpr NodeNum adapterBurstSource = 0x31313131;
static constexpr NodeNum adapterBurstDestination = 0x42424242;
static uint8_t adapterBurstDestinationPrivateKey[32] = {};

static W12BenchmarkModule::RunConfig adapterBurstRun()
{
    W12BenchmarkModule::RunConfig run;
    run.runId = 0x55667788;
    run.source = adapterBurstSource;
    run.destination = adapterBurstDestination;
    run.count = W12BenchmarkModule::MIN_COUNT;
    run.size = W12BenchmarkModule::DEFAULT_SIZE;
    run.durationMs = 60000;
    run.window = 4;
    return run;
}

static ProcessMessage sendAdapterBurstControl(W12BenchmarkModule::Op op)
{
    meshtastic_MeshPacket control = meshtastic_MeshPacket_init_zero;
    control.from = 0;
    control.to = adapterBurstSource;
    control.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL;
    control.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    const auto run = adapterBurstRun();
    control.decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
    control.decoded.payload.size =
        W12BenchmarkModule::encodeControl(control.decoded.payload.bytes, sizeof(control.decoded.payload.bytes), op, run);
    return adapterDiagnostics->handleReceived(control);
}

static void makeW12BurstOwnerFixture()
{
    adapterBurstSavedRouter = router;
    adapterBurstSavedService = service;
    adapterBurstSavedNodeDB = nodeDB;
    adapterBurstSavedNodeInfo = myNodeInfo;

    adapterBurstOwnedNodeDB = new AdapterBurstNodeDB();
    adapterBurstOwnedNodeDB->clearTestNodes();
    nodeDB = adapterBurstOwnedNodeDB;
    myNodeInfo = meshtastic_MyNodeInfo_init_zero;
    myNodeInfo.my_node_num = adapterBurstSource;
    config.security.private_key.size = 32;
    config.security.public_key.size = 32;
    uint8_t localPublic[32] = {};
    uint8_t localPrivate[32] = {};
    uint8_t destinationPublic[32] = {};
    uint8_t destinationPrivate[32] = {};
    crypto->generateKeyPair(localPublic, localPrivate);
    crypto->generateKeyPair(destinationPublic, destinationPrivate);
    memcpy(adapterBurstDestinationPrivateKey, destinationPrivate, sizeof(destinationPrivate));
    memcpy(config.security.private_key.bytes, localPrivate, sizeof(localPrivate));
    memcpy(config.security.public_key.bytes, localPublic, sizeof(localPublic));
    crypto->setDHPrivateKey(localPrivate);
    adapterBurstOwnedNodeDB->addPublicKey(adapterBurstDestination, destinationPublic);
    adapterBurstOwnedNodeDB->addPublicKey(adapterBurstSource, localPublic);

    makeW12Adapter();
    initRegion();
    adapterBurstOwnedRouter = new Router();
    adapterBurstOwnedRouter->addInterface(std::unique_ptr<RadioInterface>(adapter));
    router = adapterBurstOwnedRouter;
    adapterBurstOwnedService = new MeshService();
    service = adapterBurstOwnedService;
    adapterDiagnostics = new TestableW12AdapterDiagnostics();
    channels.initDefaults();
    channels.onConfigChanged();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::RESET)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::START)));
}
#endif

static constexpr NodeNum adapterDiagnosticSource = 0x11111111;
static constexpr NodeNum adapterDiagnosticDestination = 0x22222222;
static NodeDB *adapterDiagnosticsNodeDB;
static NodeDB *savedAdapterNodeDB;
static meshtastic_MyNodeInfo savedAdapterNodeInfo;

static W12BenchmarkModule::RunConfig adapterDiagnosticRun()
{
    W12BenchmarkModule::RunConfig run;
    run.runId = 0x10203040;
    run.source = adapterDiagnosticSource;
    run.destination = adapterDiagnosticDestination;
    run.count = W12BenchmarkModule::MIN_COUNT;
    run.size = W12BenchmarkModule::DEFAULT_SIZE;
    run.durationMs = 60000;
    run.window = 1;
    return run;
}

static ProcessMessage sendAdapterDiagnosticControl(W12BenchmarkModule::Op op, NodeNum localNode = adapterDiagnosticDestination)
{
    TEST_ASSERT_NOT_NULL(adapterDiagnostics);
    TEST_ASSERT_NOT_NULL(adapterDiagnosticsNodeDB);
    meshtastic_MeshPacket control = meshtastic_MeshPacket_init_zero;
    control.from = 0;
    control.to = localNode;
    control.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL;
    control.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    control.decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
    const auto run = adapterDiagnosticRun();
    control.decoded.payload.size =
        W12BenchmarkModule::encodeControl(control.decoded.payload.bytes, sizeof(control.decoded.payload.bytes), op, run);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::CONTROL_BYTES, control.decoded.payload.size);
    return adapterDiagnostics->handleReceived(control);
}

static void prepareAdapterDiagnostics()
{
    savedAdapterNodeDB = nodeDB;
    savedAdapterNodeInfo = myNodeInfo;
    adapterDiagnosticsNodeDB = new NodeDB();
    nodeDB = adapterDiagnosticsNodeDB;
    myNodeInfo.my_node_num = adapterDiagnosticDestination;
    adapterDiagnostics = new TestableW12AdapterDiagnostics();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::RESET)));
}

static void startAdapterDiagnostics()
{
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::START)));
}

static void makeW12AdapterWithDiagnostics()
{
    prepareAdapterDiagnostics();
    makeW12Adapter();
    startAdapterDiagnostics();
}

#if W12_BENCHMARK_HAL_TIMING_ENABLED
static void test_w12_production_hal_controls_collect_end_to_end()
{
    prepareAdapterDiagnostics();
    auto *production = new W12ProductionHalAdapter();
    myNodeInfo.my_node_num = adapterDiagnosticSource;

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::RESET, adapterDiagnosticSource)));
    TEST_ASSERT_EQUAL_INT(
        static_cast<int>(ProcessMessage::STOP),
        static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::ENABLE_SPI_YIELD, adapterDiagnosticSource)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::START, adapterDiagnosticSource)));

    auto snapshot = production->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(4000000, snapshot.requestedHz);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT32(0, snapshot.yieldCount);
    production->exerciseProductionHal();
    snapshot = production->getW12HalTiming();
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.transferCount);
    TEST_ASSERT_EQUAL_UINT64(64, snapshot.transferredBytes);
    TEST_ASSERT_EQUAL_UINT32(1, snapshot.yieldCount);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::STOP, adapterDiagnosticSource)));
    snapshot = production->getW12HalTiming();
    TEST_ASSERT_TRUE(snapshot.frozen);
    TEST_ASSERT_EQUAL_INT(
        static_cast<int>(ProcessMessage::STOP),
        static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::SNAPSHOT_SPI_YIELD, adapterDiagnosticSource)));
    delete production;
}
#endif

static size_t adapterIrqStatusReadCount()
{
    size_t count = 0;
    for (const auto &transaction : adapterHal->recording.transactions) {
        if (transaction.size() == 6 &&
            std::all_of(transaction.begin(), transaction.end(), [](uint8_t byte) { return byte == 0; }))
            ++count;
    }
    return count;
}

struct AdapterRxLivenessReply {
    uint8_t bytes[W12BenchmarkModule::RX_LIVENESS_REPORT_BYTES] = {};
};

struct AdapterPreSendAttributionReply {
    uint8_t bytes[W12BenchmarkModule::PRE_SEND_ATTRIBUTION_REPORT_BYTES] = {};
};

static uint16_t adapterRxLivenessU16(const AdapterRxLivenessReply &reply, size_t offset)
{
    return uint16_t(reply.bytes[offset]) | (uint16_t(reply.bytes[offset + 1]) << 8);
}

static uint32_t adapterRxLivenessU32(const AdapterRxLivenessReply &reply, size_t offset)
{
    return uint32_t(reply.bytes[offset]) | (uint32_t(reply.bytes[offset + 1]) << 8) | (uint32_t(reply.bytes[offset + 2]) << 16) |
           (uint32_t(reply.bytes[offset + 3]) << 24);
}

static int16_t adapterRxLivenessI16(const AdapterRxLivenessReply &reply, size_t offset)
{
    return static_cast<int16_t>(adapterRxLivenessU16(reply, offset));
}

static AdapterRxLivenessReply takeAdapterRxLivenessReply()
{
    auto *reply = adapterDiagnostics->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RX_LIVENESS_REPORT_BYTES, reply->decoded.payload.size);
    AdapterRxLivenessReply result;
    memcpy(result.bytes, reply->decoded.payload.bytes, sizeof(result.bytes));
    packetPool.release(reply);
    return result;
}

static AdapterPreSendAttributionReply takeAdapterPreSendAttributionReply()
{
    auto *reply = adapterDiagnostics->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::PRE_SEND_ATTRIBUTION_REPORT_BYTES, reply->decoded.payload.size);
    AdapterPreSendAttributionReply result;
    memcpy(result.bytes, reply->decoded.payload.bytes, sizeof(result.bytes));
    packetPool.release(reply);
    return result;
}

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
struct AdapterRadioGapsReply {
    uint8_t bytes[W12BenchmarkModule::RADIO_GAPS_REPORT_BYTES] = {};
};

static uint32_t adapterRadioGapsU32(const AdapterRadioGapsReply &reply, size_t offset)
{
    return uint32_t(reply.bytes[offset]) | (uint32_t(reply.bytes[offset + 1]) << 8) | (uint32_t(reply.bytes[offset + 2]) << 16) |
           (uint32_t(reply.bytes[offset + 3]) << 24);
}

static AdapterRadioGapsReply takeAdapterRadioGapsReply()
{
    auto *reply = adapterDiagnostics->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RADIO_GAPS_REPORT_BYTES, reply->decoded.payload.size);
    AdapterRadioGapsReply result;
    memcpy(result.bytes, reply->decoded.payload.bytes, sizeof(result.bytes));
    packetPool.release(reply);
    return result;
}
#endif

static uint16_t adapterPreSendU16(const AdapterPreSendAttributionReply &reply, size_t offset)
{
    return uint16_t(reply.bytes[offset]) | (uint16_t(reply.bytes[offset + 1]) << 8);
}

static uint32_t adapterPreSendU32(const AdapterPreSendAttributionReply &reply, size_t offset)
{
    return uint32_t(reply.bytes[offset]) | (uint32_t(reply.bytes[offset + 1]) << 8) | (uint32_t(reply.bytes[offset + 2]) << 16) |
           (uint32_t(reply.bytes[offset + 3]) << 24);
}

static int16_t adapterPreSendI16(const AdapterPreSendAttributionReply &reply, size_t offset)
{
    return static_cast<int16_t>(adapterPreSendU16(reply, offset));
}

static ProcessMessage sendAdapterDiagnosticData(uint32_t sequence = 0)
{
    meshtastic_MeshPacket data = meshtastic_MeshPacket_init_zero;
    data.from = adapterDiagnosticSource;
    data.to = adapterDiagnosticDestination;
    data.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    data.pki_encrypted = true;
    data.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    data.decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
    const auto run = adapterDiagnosticRun();
    data.decoded.payload.size =
        W12BenchmarkModule::encodeData(data.decoded.payload.bytes, sizeof(data.decoded.payload.bytes), run, sequence);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::DEFAULT_SIZE, data.decoded.payload.size);
    return adapterDiagnostics->handleReceived(data);
}

static void prepareAdapterDiagnosticReceiverWindow()
{
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE), static_cast<int>(sendAdapterDiagnosticData()));
}

static meshtastic_MeshPacket *makeAdapterTransmission();
static void prepareAdapterReception();
#endif

static AirTime *savedAdapterAirTime;
static PowerMon *savedAdapterPowerMon;

class AdapterPacketReceiver : public Router
{
  public:
    void enqueueReceivedMessage(meshtastic_MeshPacket *packet) override
    {
        packets.push_back(*packet);
        packetPool.release(packet);
    }
    std::vector<meshtastic_MeshPacket> packets;
};

static AdapterPacketReceiver *adapterReceiver;
static Router *savedAdapterRouter;

static void makeW12Adapter()
{
    Time::setTestMillis(100);
    config.lora = meshtastic_Config_LoRaConfig_init_zero;
    config.lora.region = meshtastic_Config_LoRaConfig_RegionCode_US;
    config.lora.has_radio_mode = true;
    config.lora.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_FLRC;
    config.lora.tx_enabled = true;
    RadioMode::initialize(config.lora);
    savedAdapterAirTime = airTime;
    savedAdapterPowerMon = powerMon;
    airTime = new AirTime();
    powerMon = new PowerMon();
    adapterHal = new W12AdapterHal();
    adapter = new TestableW12Adapter(adapterHal);
#ifdef MESHNOLOGY_W12
    TEST_ASSERT_TRUE(adapter->init());
#else
    // Native has no W12 capability; exercise the same recovery/RX paths without enabling TX policy.
    TEST_ASSERT_TRUE(adapter->recover());
    adapter->armReceive();
#endif
    TEST_ASSERT_FALSE(adapter->isOffline());
    TEST_ASSERT_TRUE(adapter->receiving());
}

static void deleteW12Adapter()
{
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
    delete adapterOwnedTxHook;
    adapterOwnedTxHook = nullptr;
#endif
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
    if (adapterBurstOwnedRouter) {
        // A receive-only auth test intentionally leaves its producer packet queued. Retire
        // physical ownership before destroying the diagnostic slots, also after Unity longjmp.
        while (adapter && adapter->frontForTest()) {
            const auto *queued = adapter->frontForTest();
            adapter->cancelSending(queued->from, queued->id);
        }
        if (adapterDiagnostics) {
            delete adapterDiagnostics;
            adapterDiagnostics = nullptr;
            w12BenchmarkModule = nullptr;
        }
        MeshService *ownedService = adapterBurstOwnedService;
        Router *ownedRouter = adapterBurstOwnedRouter;
        router = adapterBurstSavedRouter;
        service = adapterBurstSavedService;
        nodeDB = adapterBurstSavedNodeDB;
        myNodeInfo = adapterBurstSavedNodeInfo;
        adapterBurstOwnedService = nullptr;
        adapterBurstOwnedRouter = nullptr;
        delete ownedService;
        delete ownedRouter; // owns and destroys the production adapter
        adapter = nullptr;
        delete adapterHal;
        adapterHal = nullptr;
        delete airTime;
        airTime = savedAdapterAirTime;
        delete powerMon;
        powerMon = savedAdapterPowerMon;
        delete adapterBurstOwnedNodeDB;
        adapterBurstOwnedNodeDB = nullptr;
        Time::useRealClock();
        return;
    }
#endif
    if (adapter) {
        adapter->releaseQueuedTransmissions();
        delete adapter;
        adapter = nullptr;
        delete adapterHal;
        adapterHal = nullptr;
        delete airTime;
        airTime = savedAdapterAirTime;
        delete powerMon;
        powerMon = savedAdapterPowerMon;
    }
    if (adapterReceiver) {
        router = savedAdapterRouter;
        delete adapterReceiver;
        adapterReceiver = nullptr;
    }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (adapterDiagnostics) {
        delete adapterDiagnostics;
        adapterDiagnostics = nullptr;
        w12BenchmarkModule = nullptr;
    }
    if (adapterDiagnosticsNodeDB) {
        nodeDB = savedAdapterNodeDB;
        delete adapterDiagnosticsNodeDB;
        adapterDiagnosticsNodeDB = nullptr;
        myNodeInfo = savedAdapterNodeInfo;
    }
#endif
    Time::useRealClock();
}

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
// W12BenchmarkModule's radio page must reflect the adapter's real arm stages and RadioLib return
// codes. These cases guard against diagnostic counters drifting away from standby/start/IRQ-map
// failures, or the poll page requiring a second SPI read for the chip mode/status bytes.
static void test_w12_adapter_rx_liveness_snapshot_reads_stats_irq_and_rssi_once()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterDiagnosticReceiverWindow();
    adapterHal->irq = 0x12345678;
    adapterHal->rawStatusMode = 0x04;
    adapterHal->rxStatsPackets = 0x1234;
    adapterHal->rxStatsCrcErrors = 0x0023;
    adapterHal->rxStatsLenErrors = 0x0045;
    adapterHal->rssiHalfDbm = 220;
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_TRUE(adapter->receiving());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS)));
    const auto reply = takeAdapterRxLivenessReply();
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::RX_LIVENESS), reply.bytes[3]);
    TEST_ASSERT_EQUAL_UINT8(35, reply.bytes[20]);
    TEST_ASSERT_EQUAL_UINT32(1, adapterRxLivenessU32(reply, 24));
    TEST_ASSERT_EQUAL_UINT8(39, reply.bytes[32]);
    TEST_ASSERT_EQUAL_UINT8(1, reply.bytes[33]);
    TEST_ASSERT_EQUAL_UINT32(0x12345678, adapterRxLivenessU32(reply, 52));
    TEST_ASSERT_EQUAL_UINT16(0x0404, adapterRxLivenessU16(reply, 56));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 58));
    TEST_ASSERT_EQUAL_UINT16(0x1234, adapterRxLivenessU16(reply, 60));
    TEST_ASSERT_EQUAL_UINT16(0x0023, adapterRxLivenessU16(reply, 62));
    TEST_ASSERT_EQUAL_UINT16(0x0045, adapterRxLivenessU16(reply, 64));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 66));
    TEST_ASSERT_EQUAL_INT16(-110, adapterRxLivenessI16(reply, 68));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 70));
    TEST_ASSERT_EQUAL_UINT32(0x15, adapterRxLivenessU32(reply, 72));
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_RX_STATS)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RSSI_INST)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterIrqStatusReadCount());
    TEST_ASSERT_EQUAL_UINT32(5, adapterHal->recording.transactions.size());
}

static void test_w12_adapter_pre_send_snapshot_reads_raw_rx_state_without_clearing()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterDiagnosticReceiverWindow();
    adapterHal->irq = 0x12345678;
    adapterHal->rawStatusMode = 0x04;
    adapterHal->fifoRxFlags = 0x12;
    adapterHal->fifoTxFlags = 0x34;
    adapterHal->rxFifoLevel = 0x4567;
    adapterHal->chipErrors = 0x89AB;
    adapterHal->busyLevel = 0;
    adapterHal->dioLevel = 1;
    adapterHal->recording.transactions.clear();

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::SNAPSHOT_PRE_SEND_ATTRIBUTION)));
    const auto reply = takeAdapterPreSendAttributionReply();
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::PRE_SEND_ATTRIBUTION), reply.bytes[3]);
    TEST_ASSERT_EQUAL_UINT8(1, reply.bytes[73]);
    TEST_ASSERT_EQUAL_UINT8(31, reply.bytes[74]);
    TEST_ASSERT_EQUAL_UINT8(1, reply.bytes[75]);
    TEST_ASSERT_EQUAL_UINT8(0, reply.bytes[76]);
    TEST_ASSERT_EQUAL_UINT32(0x12345678, adapterPreSendU32(reply, 86));
    TEST_ASSERT_EQUAL_UINT16(0x0404, adapterPreSendU16(reply, 90));
    TEST_ASSERT_EQUAL_UINT16(0x4567, adapterPreSendU16(reply, 92));
    TEST_ASSERT_EQUAL_UINT8(0x12, reply.bytes[94]);
    TEST_ASSERT_EQUAL_UINT8(0x34, reply.bytes[95]);
    TEST_ASSERT_EQUAL_UINT16(0x89AB, adapterPreSendU16(reply, 96));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterPreSendI16(reply, 98));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterPreSendI16(reply, 100));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterPreSendI16(reply, 102));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterPreSendI16(reply, 104));
    TEST_ASSERT_EQUAL_UINT32(0x15, adapterPreSendU32(reply, 106));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_FIFO_IRQ_FLAGS)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RX_FIFO_LEVEL)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_ERRORS)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_ERRORS)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_FIFO_IRQ_FLAGS)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_AND_CLEAR_FIFO_IRQ_FLAGS)));
    TEST_ASSERT_TRUE(adapter->receiving());
}

static void test_w12_adapter_active_rx_failure_is_classified_by_one_irq_read()
{
    makeW12AdapterWithDiagnostics();
    adapterHal->rawStatusFailed = true;
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12ActiveReceiveState::IRQ_READ_FAILURE),
                            static_cast<uint8_t>(adapter->activeReceiveState()));
    TEST_ASSERT_EQUAL_UINT32(1, adapterIrqStatusReadCount());
}

static void test_w12_adapter_rx_liveness_snapshot_reports_chip_stats_failure()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterDiagnosticReceiverWindow();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_GET_FLRC_RX_STATS;
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS)));
    const auto reply = takeAdapterRxLivenessReply();
    TEST_ASSERT_EQUAL_UINT8(37, reply.bytes[32]);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, adapterRxLivenessI16(reply, 66));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 58));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 70));
    TEST_ASSERT_EQUAL_UINT32(5, adapterHal->recording.transactions.size());
}

static void test_w12_adapter_rx_liveness_snapshot_reports_irq_status_failure()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterDiagnosticReceiverWindow();
    adapterHal->rawStatusFailed = true;
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS)));
    const auto reply = takeAdapterRxLivenessReply();
    TEST_ASSERT_EQUAL_UINT8(38, reply.bytes[32]);
    TEST_ASSERT_EQUAL_UINT32(0, adapterRxLivenessU32(reply, 52));
    TEST_ASSERT_EQUAL_UINT16(0, adapterRxLivenessU16(reply, 56));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, adapterRxLivenessI16(reply, 58));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 66));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 70));
}

static void test_w12_adapter_rx_liveness_snapshot_reports_rssi_failure()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterDiagnosticReceiverWindow();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_GET_RSSI_INST;
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS)));
    const auto reply = takeAdapterRxLivenessReply();
    TEST_ASSERT_EQUAL_UINT8(35, reply.bytes[32]);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 58));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapterRxLivenessI16(reply, 66));
    TEST_ASSERT_EQUAL_INT16(INT16_MIN, adapterRxLivenessI16(reply, 68));
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, adapterRxLivenessI16(reply, 70));
}

static void test_w12_adapter_rx_liveness_rearms_once_and_guards_active_or_queued_tx()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterDiagnosticReceiverWindow();
    adapter->stop();
    auto *activePacket = makeAdapterTransmission();
    TEST_ASSERT_EQUAL_UINT32(10 + sizeof(PacketHeader), adapter->takeTransmission(activePacket));
    TEST_ASSERT_TRUE(adapter->isSending());
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::REARM_RX_LIVENESS)));
    TEST_ASSERT_NULL(adapterDiagnostics->allocReply());
    TEST_ASSERT_TRUE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.transactions.size());
    adapter->stop();

    TEST_ASSERT_TRUE(adapter->queueTransmission(makeAdapterTransmission()));
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::REARM_RX_LIVENESS)));
    TEST_ASSERT_NULL(adapterDiagnostics->allocReply());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.transactions.size());
    adapter->releaseQueuedTransmissions();

    adapter->armReceive();
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::REARM_RX_LIVENESS)));
    const auto reply = takeAdapterRxLivenessReply();
    TEST_ASSERT_EQUAL_UINT32(1, adapterRxLivenessU32(reply, 34));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxLivenessRearmResult::SOFTWARE_ARMED), reply.bytes[38]);
    TEST_ASSERT_EQUAL_UINT8(0x15, reply.bytes[39]);
    TEST_ASSERT_EQUAL_UINT8(0x15, reply.bytes[40]);
    TEST_ASSERT_TRUE(reply.bytes[32] & 0x08);
    TEST_ASSERT_TRUE(reply.bytes[32] & 0x10);

    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendAdapterDiagnosticControl(W12BenchmarkModule::Op::REARM_RX_LIVENESS)));
    TEST_ASSERT_NULL(adapterDiagnostics->allocReply());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.transactions.size());
}

static void test_w12_adapter_rx_liveness_does_not_add_stats_or_rssi_reads_to_receive_isr()
{
    makeW12AdapterWithDiagnostics();
    adapterHal->recording.transactions.clear();
    adapterHal->irq = 0;
    adapter->receiveInterrupt();
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_RX_STATS)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RSSI_INST)));
    // The ISR reads IRQ status once. Clearing zero IRQ adds a status transfer
    // only when RadioLib's optional post-write verification is enabled.
    TEST_ASSERT_EQUAL_UINT32(RADIOLIB_SPI_PARANOID ? 2 : 1, adapterIrqStatusReadCount());
}

static void test_w12_adapter_radio_diagnostics_counts_successful_arm_stages()
{
    makeW12AdapterWithDiagnostics();
    adapter->armReceive();
    const auto diagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmAttempts);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmSuccesses);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStandbyCalls);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxStandbyFailures);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxStandbyLastResult);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStartCalls);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxStartFailures);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxStartLastResult);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxStartRetryCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxIrqMapCalls);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxIrqMapFailures);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxIrqMapLastResult);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxArmLastResult);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxArmStage::NONE), diagnostics.rxArmLastStage);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStartDurationCountUs);
}

static void test_w12_adapter_radio_diagnostics_counts_standby_failure_and_result()
{
    makeW12AdapterWithDiagnostics();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_STANDBY;
    adapterHal->failCommandOccurrence = 1;
    adapter->armReceive();
    const auto diagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmAttempts);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmSuccesses);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStandbyCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStandbyFailures);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, diagnostics.rxStandbyLastResult);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStartCalls);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxStartFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStartRetryCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxIrqMapCalls);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxArmLastResult);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxArmStage::NONE), diagnostics.rxArmLastStage);
    TEST_ASSERT_FALSE(adapter->isOffline());
}

static void test_w12_adapter_radio_diagnostics_counts_start_failure_retry_and_result()
{
    makeW12AdapterWithDiagnostics();
    adapterHal->recording.transactions.clear();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_RX;
    adapter->armReceive();
    const auto diagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmAttempts);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxArmSuccesses);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStandbyCalls);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxStandbyLastResult);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.rxStartCalls);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.rxStartFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStartRetryCalls);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, diagnostics.rxStartLastResult);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxIrqMapCalls);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, diagnostics.rxArmLastResult);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxArmStage::RX_START), diagnostics.rxArmLastStage);
    TEST_ASSERT_TRUE(adapter->isOffline());
    TEST_ASSERT_EQUAL_UINT32(2, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();
}

static void test_w12_adapter_radio_diagnostics_counts_irq_map_failure_and_result()
{
    makeW12AdapterWithDiagnostics();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_DIO_IRQ_CONFIG;
    adapterHal->failCommandOccurrence = 2;
    adapter->armReceive();
    const auto diagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmAttempts);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxArmSuccesses);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStandbyCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStartCalls);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxStartRetryCalls);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxStartLastResult);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxIrqMapCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxIrqMapFailures);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, diagnostics.rxIrqMapLastResult);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, diagnostics.rxArmLastResult);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxArmStage::IRQ_MAP), diagnostics.rxArmLastStage);
    TEST_ASSERT_TRUE(adapter->isOffline());
}

static void test_w12_adapter_radio_diagnostics_poll_reads_raw_status_once()
{
    makeW12AdapterWithDiagnostics();
    adapterHal->rawStatusMode = 0x04;
    adapterHal->recording.transactions.clear();
    adapterHal->irq = 0;
    adapter->pollMissedIrqs();
    const auto diagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.pollCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.pollRxChecks);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.pollRxReadSuccess);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.pollRxReadFailure);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.pollRxPending);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.pollRxLastFlags);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.pollRxLastResult);
    TEST_ASSERT_EQUAL_UINT8(0x04, diagnostics.pollChipStatus0);
    TEST_ASSERT_EQUAL_UINT8(0x04, diagnostics.pollChipStatus1);
    TEST_ASSERT_EQUAL_UINT8(1, diagnostics.pollChipStatusObserved);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.pollChipRxCount);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.pollChipNonRxCount);
    TEST_ASSERT_EQUAL_UINT32(1, adapterIrqStatusReadCount());

    adapterHal->rawStatusMode = 0x01;
    adapter->pollMissedIrqs();
    const auto secondDiagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(2, secondDiagnostics.pollCalls);
    TEST_ASSERT_EQUAL_UINT32(2, secondDiagnostics.pollRxChecks);
    TEST_ASSERT_EQUAL_UINT32(2, secondDiagnostics.pollRxReadSuccess);
    TEST_ASSERT_EQUAL_UINT8(0x04, secondDiagnostics.pollChipStatus0);
    TEST_ASSERT_EQUAL_UINT8(0x01, secondDiagnostics.pollChipStatus1);
    TEST_ASSERT_EQUAL_UINT32(1, secondDiagnostics.pollChipRxCount);
    TEST_ASSERT_EQUAL_UINT32(1, secondDiagnostics.pollChipNonRxCount);
    TEST_ASSERT_EQUAL_UINT32(2, adapterIrqStatusReadCount());
}

static void test_w12_adapter_radio_diagnostic_software_irq_state_tracks_standby_and_rx()
{
    makeW12AdapterWithDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(0x15, adapter->getW12DiagnosticRadioState());
    adapter->stop();
    TEST_ASSERT_EQUAL_UINT32(0x10, adapter->getW12DiagnosticRadioState());
    adapter->armReceive();
    TEST_ASSERT_EQUAL_UINT32(0x15, adapter->getW12DiagnosticRadioState());
}

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
// A real RX_DONE notification must pass through the RadioLib adapter's read, queue, and RX
// rearm path before the owner gap page records one valid sample.
static void test_w12_adapter_owner_gap_rx_done_notification_records_rearm()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterReception();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    const auto gaps = adapterDiagnostics->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(1, gaps.rxNotifications);
    TEST_ASSERT_EQUAL_UINT32(1, gaps.rxValidDone);
    TEST_ASSERT_EQUAL_UINT32(0, gaps.rxInvalid);
    TEST_ASSERT_EQUAL_UINT32(0, gaps.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, gaps.ownerRxNotifyToRearmUs.count);
    TEST_ASSERT_TRUE(adapter->receiving());
}

// A frame that was read successfully but cannot rearm RX is an invalid owner sample. It must
// keep the read delivery while excluding the failed rearm from the timing metric.
static void test_w12_adapter_owner_gap_rx_rearm_failure_is_invalid_without_sample()
{
    makeW12AdapterWithDiagnostics();
    prepareAdapterReception();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_RX;
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    const auto gaps = adapterDiagnostics->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(1, gaps.rxNotifications);
    TEST_ASSERT_EQUAL_UINT32(1, gaps.rxValidDone);
    TEST_ASSERT_EQUAL_UINT32(1, gaps.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, gaps.rxInvalid);
    TEST_ASSERT_EQUAL_UINT32(0, gaps.ownerRxNotifyToRearmUs.count);
    TEST_ASSERT_TRUE(adapter->isOffline());
}
#endif
#endif

static void test_w12_adapter_recovery_preserves_active_flrc_and_rearms_rx()
{
    makeW12Adapter();
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapter->changeCrc(2));
    config.lora.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_LORA;
    adapterHal->recording.transactions.clear();
    TEST_ASSERT_TRUE(adapter->recover());
    adapter->armReceive();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->isOffline());
    TEST_ASSERT_TRUE(RadioMode::isFlrc());
    TEST_ASSERT_EQUAL_UINT32(2769, adapter->driverDuration(255));
    TEST_ASSERT_GREATER_THAN_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_FLRC_SYNCWORD)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_LORA_MODULATION_PARAMS)));
    const auto *irqConfig = adapterHal->recording.last(op16(RADIOLIB_LR2021_CMD_SET_DIO_IRQ_CONFIG));
    TEST_ASSERT_NOT_NULL(irqConfig);
    TEST_ASSERT_EQUAL_UINT8(8, (*irqConfig)[2]);
    uint32_t flags = (uint32_t((*irqConfig)[3]) << 24) | (uint32_t((*irqConfig)[4]) << 16) | (uint32_t((*irqConfig)[5]) << 8) |
                     (*irqConfig)[6];
    TEST_ASSERT_EQUAL_UINT32(W12FlrcProfile::RECEIVE_IRQS, flags);
}

static void test_w12_adapter_rx_arm_uses_configured_fallback_and_expected_timeout()
{
    makeW12Adapter();
    const auto *fallback = adapterHal->recording.last(op16(RADIOLIB_LR2021_CMD_SET_RX_TX_FALLBACK_MODE));
    TEST_ASSERT_NOT_NULL(fallback);
    TEST_ASSERT_GREATER_OR_EQUAL_size_t(3, fallback->size());
    TEST_ASSERT_EQUAL_UINT8(RADIOLIB_LR2021_FALLBACK_MODE_STBY_RC, (*fallback)[2]);
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();
}

// The finite-RX experiment opts into an explicit FIFO reset between standby and RX start;
// the default build must retain the existing arm sequence.
static void test_w12_adapter_rx_arm_fifo_clear_is_opt_in()
{
    makeW12Adapter();
    adapterHal->recording.transactions.clear();
    adapter->armReceive();

#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
    const size_t standbyIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_STANDBY), 1);
    const size_t clearIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO), 1);
    const size_t setRxIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_RX), 1);
    TEST_ASSERT_TRUE(standbyIndex < clearIndex);
    TEST_ASSERT_TRUE(clearIndex < setRxIndex);
#else
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
#endif
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();
}

#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS)
// A finite chip timeout is diagnostic only: every normal ISR/poll path must reject TIMEOUT, clear it,
// and re-arm RX with the same measured 24-bit timeout without reading a payload.
static void assertFiniteTimeoutRearm(uint32_t expectedBadReceives)
{
    TEST_ASSERT_EQUAL_UINT32(expectedBadReceives, adapter->badReceives());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->isOffline());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->irq);
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();

    const size_t clearIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ), 1);
    const size_t standbyIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_STANDBY), 1);
    const size_t dioBeforeIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_DIO_IRQ_CONFIG), 1);
    const size_t setRxIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_RX), 1);
    const size_t dioAfterIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_DIO_IRQ_CONFIG), 2);
    const auto *dioBefore = adapterHal->recording.first(op16(RADIOLIB_LR2021_CMD_SET_DIO_IRQ_CONFIG));
    TEST_ASSERT_NOT_NULL(dioBefore);
    TEST_ASSERT_GREATER_OR_EQUAL_size_t(7, dioBefore->size());
    const uint32_t dioBeforeFlags = (uint32_t((*dioBefore)[3]) << 24) | (uint32_t((*dioBefore)[4]) << 16) |
                                    (uint32_t((*dioBefore)[5]) << 8) | (*dioBefore)[6];
    TEST_ASSERT_TRUE(dioBeforeFlags & RADIOLIB_LR2021_IRQ_TIMEOUT);
    TEST_ASSERT_TRUE(setRxIndex < adapterHal->recording.transactions.size());
    TEST_ASSERT_TRUE(clearIndex < standbyIndex);
    TEST_ASSERT_TRUE(standbyIndex < dioBeforeIndex);
    TEST_ASSERT_TRUE(dioBeforeIndex < setRxIndex);
    TEST_ASSERT_TRUE(setRxIndex < dioAfterIndex);
}

static void test_w12_adapter_finite_timeout_rejects_and_rearms()
{
    makeW12Adapter();
    const uint32_t badBefore = adapter->badReceives();

    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_TIMEOUT);
    adapter->serviceNotifications();
    assertFiniteTimeoutRearm(badBefore + 1);

    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_TIMEOUT);
    adapter->serviceNotifications();
    assertFiniteTimeoutRearm(badBefore + 2);

    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_TIMEOUT);
    adapter->serviceNotifications();
    assertFiniteTimeoutRearm(badBefore + 3);

    adapterHal->recording.transactions.clear();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TIMEOUT;
    adapter->pollMissedIrqs();
    adapter->serviceNotifications();
    assertFiniteTimeoutRearm(badBefore + 4);
}

#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
// A W12FlrcProfile::clearRxFifo failure must leave LR2021Interface::startReceive before
// lora.startReceive and its recovery retry, then recover only through the later maintenance path.
static void test_w12_adapter_fifo_clear_failure_stays_offline_until_retry()
{
    makeW12AdapterWithDiagnostics();
    adapterHal->recording.transactions.clear();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO;
    adapter->armReceive();

    auto diagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmAttempts);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxArmSuccesses);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStandbyCalls);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxStartCalls);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxIrqMapCalls);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, diagnostics.rxArmLastResult);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxArmStage::FIFO_CLEAR), diagnostics.rxArmLastStage);
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_TRUE(adapter->isOffline());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_FALSE(RadioMode::status(config.lora).active_initialized);

    adapterHal->failCommand = 0;
    Time::advanceTestMillis(30000);
    adapter->periodicRadioMaintenance();

    diagnostics = adapterDiagnostics->getRadioDiagnostics();
    TEST_ASSERT_FALSE(adapter->isOffline());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.rxArmAttempts);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmSuccesses);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.rxStandbyCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxStartCalls);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxIrqMapCalls);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, diagnostics.rxArmLastResult);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxArmStage::NONE), diagnostics.rxArmLastStage);
    TEST_ASSERT_EQUAL_UINT32(2, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();
}

static void test_w12_adapter_terminal_errors_rearm_fifo_without_reading_payload()
{
    makeW12Adapter();
    constexpr uint32_t terminalErrors[] = {RADIOLIB_LR2021_IRQ_CRC_ERROR, RADIOLIB_LR2021_IRQ_LEN_ERROR,
                                           RADIOLIB_LR2021_IRQ_TIMEOUT};
    for (size_t index = 0; index < sizeof(terminalErrors) / sizeof(terminalErrors[0]); ++index) {
        adapterHal->recording.transactions.clear();
        adapterHal->irq = RADIOLIB_LR2021_IRQ_RX_DONE | terminalErrors[index];
        adapter->receiveInterrupt();
        TEST_ASSERT_EQUAL_UINT32(index + 1, adapter->badReceives());
        TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
        TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));

        adapter->armReceive();
        TEST_ASSERT_TRUE(adapter->receiving());
        TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
        TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
        const size_t standbyIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_STANDBY), 1);
        const size_t clearIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO), 1);
        const size_t setRxIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_RX), 1);
        TEST_ASSERT_TRUE(standbyIndex < clearIndex);
        TEST_ASSERT_TRUE(clearIndex < setRxIndex);
        assertAdapterSetRxTimeout();
    }
}
#endif
#endif

static void test_w12_adapter_failed_rx_remains_offline_until_successful_rearm()
{
    makeW12Adapter();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_RX;
    adapter->armReceive();
    TEST_ASSERT_TRUE(adapter->isOffline());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_FALSE(RadioMode::status(config.lora).active_initialized);
    TEST_ASSERT_TRUE(adapter->channelActive());
    size_t attempts = adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_FLRC_SYNCWORD));
    adapter->periodicRadioMaintenance();
    TEST_ASSERT_EQUAL_UINT32(attempts, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_FLRC_SYNCWORD)));
    adapterHal->failCommand = 0;
    Time::advanceTestMillis(30000);
    adapter->periodicRadioMaintenance();
    TEST_ASSERT_FALSE(adapter->isOffline());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_TRUE(RadioMode::status(config.lora).active_initialized);
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_LORA_MODULATION_PARAMS)));
}

static void test_w12_adapter_sensing_busy_and_failed_reads_defer_without_lora_cad()
{
    makeW12Adapter();
    adapterHal->rssiHalfDbm = 160;
    TEST_ASSERT_TRUE(adapter->channelActive());
    TEST_ASSERT_TRUE(adapter->receiving());
    adapterHal->rssiHalfDbm = 220;
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_GET_RSSI_INST;
    TEST_ASSERT_TRUE(adapter->channelActive());
    adapterHal->failCommand = 0;
    adapter->armReceive();
    TEST_ASSERT_FALSE(adapter->channelActive());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_LORA_CAD)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_LORA_MODULATION_PARAMS)));
}

static void test_w12_adapter_terminal_rx_error_rejects_payload_and_rearms()
{
    makeW12Adapter();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_LEN_ERROR;
    adapter->receiveInterrupt();
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    adapterHal->irq = 0;
    adapter->armReceive();
    TEST_ASSERT_TRUE(adapter->receiving());
    adapterHal->recording.transactions.clear();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_CRC_ERROR;
    adapter->receiveInterrupt();
    TEST_ASSERT_EQUAL_UINT32(2, adapter->badReceives());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    adapterHal->irq = 0;
    adapter->armReceive();
    TEST_ASSERT_TRUE(adapter->receiving());
    assertAdapterSetRxTimeout();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_SYNCWORD_VALID;
    TEST_ASSERT_TRUE(adapter->receiveActive());
    Time::advanceTestMillis(W12FlrcProfile::durationMs(MAX_LORA_PAYLOAD_LEN));
    TEST_ASSERT_FALSE(adapter->receiveActive());
}

// A command-error status can arrive with stale completion bits. Neither sensing nor
// packet handling may turn those bytes into a successful RF observation.
static void test_w12_adapter_failed_irq_status_keeps_channel_busy_and_rejects_stale_rx()
{
    makeW12Adapter();
    adapterHal->rawStatusFailed = true;
    TEST_ASSERT_TRUE(adapter->receiveActive());
    TEST_ASSERT_TRUE(adapter->channelActive());
    TEST_ASSERT_TRUE(adapter->receiving());
    adapterHal->irq = RADIOLIB_LR2021_IRQ_RX_DONE;
    adapter->receiveInterrupt();
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    adapterHal->rawStatusFailed = false;
    adapter->armReceive();
    TEST_ASSERT_TRUE(adapter->receiving());
}

static void test_w12_adapter_transmit_requires_tx_done_and_never_double_completes()
{
    makeW12Adapter();
    adapter->stop();
    auto *packet = packetPool.allocZeroed();
    packet->from = 0x1234;
    packet->to = NODENUM_BROADCAST;
    packet->which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    packet->encrypted.size = 10;
    TEST_ASSERT_EQUAL_UINT32(10 + sizeof(PacketHeader), adapter->takeTransmission(packet));
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TIMEOUT;
    adapter->transmitInterrupt();
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(1, adapter->droppedTransmits());
    TEST_ASSERT_FALSE(adapter->isSending());
    adapter->transmitInterrupt();
    TEST_ASSERT_EQUAL_UINT16(1, adapter->droppedTransmits());
    packet = packetPool.allocZeroed();
    packet->from = 0x1234;
    packet->to = NODENUM_BROADCAST;
    packet->which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    packet->encrypted.size = MAX_RADIO_PAYLOAD_LEN;
    TEST_ASSERT_EQUAL_UINT32(MAX_LORA_PAYLOAD_LEN, adapter->takeTransmission(packet));
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->transmitInterrupt();
    TEST_ASSERT_EQUAL_UINT32(1, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(1, adapter->droppedTransmits());
    uint32_t reported[PERIODS_TO_LOG] = {};
    TEST_ASSERT_TRUE(airTime->airtimeReport(TX_LOG, reported, PERIODS_TO_LOG));
    TEST_ASSERT_EQUAL_UINT32(
        W12FlrcProfile::durationMs(10 + sizeof(PacketHeader)) + W12FlrcProfile::durationMs(MAX_LORA_PAYLOAD_LEN), reported[0]);
}

static void test_w12_adapter_disabling_queued_tx_restores_receive()
{
    makeW12Adapter();
    adapter->stop();
    config.lora.tx_enabled = false;
    auto *packet = packetPool.allocZeroed();
    TEST_ASSERT_FALSE(adapter->sendNow(packet));
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_TX)));
}

static int32_t packetPoolLiveBytes();

static meshtastic_MeshPacket *makeAdapterTransmission()
{
    auto *packet = packetPool.allocZeroed();
    TEST_ASSERT_NOT_NULL(packet);
    packet->from = 0x1234;
    packet->to = NODENUM_BROADCAST;
    packet->which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    packet->encrypted.size = 10;
    return packet;
}

static void prepareAdapterReception()
{
    savedAdapterRouter = router;
    adapterReceiver = new AdapterPacketReceiver();
    router = adapterReceiver;
    PacketHeader header = {};
    header.from = 0x5678;
    header.to = NODENUM_BROADCAST;
    header.id = 0x87654321;
    const uint8_t payload[] = {0x42, 0x53, 0x64};
    std::vector<uint8_t> frame(sizeof(header) + sizeof(payload));
    memcpy(frame.data(), &header, sizeof(header));
    memcpy(frame.data() + sizeof(header), payload, sizeof(payload));
    adapterHal->recording.reply(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH), 0,
                                {0x04, 0x04, 0, static_cast<uint8_t>(frame.size())}, true);
    frame.insert(frame.begin(), {0x04, 0x04});
    adapterHal->recording.reply(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO), 0, frame);
    // Stage an ordinary queued packet to reach contention handling even when native TX policy is gated.
    TEST_ASSERT_TRUE(adapter->queueTransmission(makeAdapterTransmission()));
    adapterHal->recording.transactions.clear();
    adapterHal->irqReads = 0;
    adapterHal->rawStatusReads = 0;
    adapterHal->failRawStatusOccurrence = 0;
    adapterHal->rxPacketLengthReads = 0;
    adapterHal->rxPacketLengthOverrideOccurrence = 0;
}

static void assertAdapterReceptionDeliveredOnce()
{
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    const auto &received = adapterReceiver->packets.front();
    TEST_ASSERT_EQUAL_HEX32(0x5678, received.from);
    TEST_ASSERT_EQUAL_HEX32(0x87654321, received.id);
    const uint8_t payload[] = {0x42, 0x53, 0x64};
    TEST_ASSERT_EQUAL_MEMORY(payload, received.encrypted.bytes, sizeof(payload));
    TEST_ASSERT_EQUAL_UINT32(sizeof(payload), received.encrypted.size);
    TEST_ASSERT_TRUE(received.rx_snr_unavailable);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->badReceives());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
    // readData clears the consumed frame; finite-RX arm then performs the diagnostic reset again.
    TEST_ASSERT_EQUAL_UINT32(2, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
    const size_t readIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO), 1);
    const size_t readClearIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO), 1);
    const size_t armClearIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO), 2);
    const size_t setRxIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_SET_RX), 1);
    TEST_ASSERT_TRUE(readIndex < readClearIndex);
    TEST_ASSERT_TRUE(readClearIndex < armClearIndex);
    TEST_ASSERT_TRUE(armClearIndex < setRxIndex);
#else
    TEST_ASSERT_GREATER_THAN_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
#endif
    TEST_ASSERT_GREATER_THAN_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();
    adapter->pollMissedIrqs();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
}

static void assertAdapterRejectedRxWasCleanedUp()
{
    const size_t reads = adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO));
    const size_t fifoClears = adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO));
    const size_t irqClears = adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ));
    TEST_ASSERT_EQUAL_UINT32(0, reads);
    TEST_ASSERT_GREATER_THAN_UINT32(0, fifoClears);
    TEST_ASSERT_GREATER_THAN_UINT32(0, irqClears);
    const size_t clearFifoIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO), 1);
    const size_t clearIrqIndex = adapterTransactionIndex(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ), 1);
    TEST_ASSERT_TRUE(clearFifoIndex < clearIrqIndex);
}

static void prepareAdapterDriverFrame(uint16_t length)
{
    std::vector<uint8_t> frame(length + 2, 0x04);
    for (uint16_t index = 0; index < length; ++index)
        frame[index + 2] = static_cast<uint8_t>(0xA0 + index);
    adapterHal->recording.reply(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO), 0, frame);
}

static void assertAdapterDriverReadLength(size_t length)
{
    const auto *read = adapterHal->recording.last(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO));
    TEST_ASSERT_NOT_NULL(read);
    TEST_ASSERT_EQUAL_UINT32(static_cast<uint32_t>(length + 2), static_cast<uint32_t>(read->size()));
}

static void assertAdapterDriverBytes(const uint8_t *data, size_t length)
{
    for (size_t index = 0; index < length; ++index)
        TEST_ASSERT_EQUAL_HEX8(static_cast<uint8_t>(0xA0 + index), data[index]);
}

static void test_w12_lr2021_implicit_cached_length_preserves_driver_reads()
{
    constexpr uint8_t cachedLength = 5;
    makeW12Adapter();
    adapterHal->packetTypeOverrideEnabled = true;
    adapterHal->packetTypeOverride = RADIOLIB_LR2021_PACKET_TYPE_LORA;
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapter->configureImplicitRxForTest(cachedLength));

    adapterHal->recording.transactions.clear();
    TEST_ASSERT_EQUAL_UINT32(cachedLength, adapter->driverPacketLengthForTest());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH)));

    prepareAdapterDriverFrame(cachedLength);
    constexpr size_t requestedLengths[] = {0, 2, 8};
    constexpr size_t readLengths[] = {cachedLength, 2, cachedLength};
    for (size_t index = 0; index < sizeof(requestedLengths) / sizeof(requestedLengths[0]); ++index) {
        adapterHal->recording.transactions.clear();
        adapterHal->irq = RADIOLIB_LR2021_IRQ_RX_DONE;
        uint8_t data[8] = {};
        TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapter->readDriverForTest(data, requestedLengths[index]));
        TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH)));
        assertAdapterDriverReadLength(readLengths[index]);
        assertAdapterDriverBytes(data, readLengths[index]);
    }
}

static void test_w12_lr2021_explicit_lora_prefix_preserves_driver_read()
{
    constexpr uint8_t actualLength = 5;
    constexpr size_t requestedLength = 2;
    makeW12Adapter();
    adapterHal->packetTypeOverrideEnabled = true;
    adapterHal->packetTypeOverride = RADIOLIB_LR2021_PACKET_TYPE_LORA;
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapter->configureExplicitRxForTest());
    adapterHal->recording.reply(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH), 0, {0x04, 0x04, 0, actualLength}, true);
    prepareAdapterDriverFrame(actualLength);
    adapterHal->recording.transactions.clear();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_LORA_HEADER_VALID;

    uint8_t data[actualLength] = {};
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapter->readDriverForTest(data, requestedLength));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH)));
    assertAdapterDriverReadLength(requestedLength);
    assertAdapterDriverBytes(data, requestedLength);
}

static void test_w12_lr2021_flrc_prefix_preserves_driver_read()
{
    constexpr uint8_t actualLength = 5;
    constexpr size_t requestedLength = 2;
    makeW12Adapter();
    adapterHal->recording.reply(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH), 0, {0x04, 0x04, 0, actualLength}, true);
    prepareAdapterDriverFrame(actualLength);
    adapterHal->recording.transactions.clear();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_RX_DONE;

    uint8_t data[actualLength] = {};
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, adapter->readDriverForTest(data, requestedLength));
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH)));
    assertAdapterDriverReadLength(requestedLength);
    assertAdapterDriverBytes(data, requestedLength);
}

// RadioLib 7.7.1 ignores a GET_RX_PKT_LENGTH error during its second lookup inside readData(),
// then returns success after reading zero bytes. Pin the production receive path so that a stale
// radioBuffer is rejected instead of delivered as a duplicate packet.
static void test_w12_adapter_checked_rx_length_error_rejects_stale_buffer()
{
    makeW12Adapter();
    prepareAdapterReception();

    // Seed radioBuffer with a valid frame that the failed read could otherwise deliver again.
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->badReceives());

    adapterHal->recording.transactions.clear();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH;
    adapterHal->failCommandOccurrence = 2;
    adapterHal->failCommandSeen = 0;
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    TEST_ASSERT_EQUAL_UINT32(2, adapterHal->failCommandSeen);
    TEST_ASSERT_EQUAL_UINT32(2, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH)));
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_TRUE(adapter->receiving());
    assertAdapterRejectedRxWasCleanedUp();

    // A later good frame must still use the newly checked path. The failed read must not leave
    // the prior radioBuffer contents eligible for delivery, while a fresh FIFO read is valid.
    adapterHal->failCommand = 0;
    adapterHal->failCommandOccurrence = 0;
    adapterHal->failCommandSeen = 0;
    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(2, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_HEX32(0x5678, adapterReceiver->packets[1].from);
    TEST_ASSERT_EQUAL_HEX32(0x87654321, adapterReceiver->packets[1].id);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
}

static void runW12CheckedInnerLengthRecovery(uint16_t innerLength)
{
    makeW12Adapter();
    prepareAdapterReception();

    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->badReceives());

    adapterHal->recording.transactions.clear();
    adapterHal->rxPacketLengthReads = 0;
    adapterHal->rxPacketLengthOverride = innerLength;
    adapterHal->rxPacketLengthOverrideOccurrence = 2;
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    // The outer length is the valid 19-byte frame. The second lookup is deliberately zero or
    // shorter than that frame, so it must reject before any FIFO read can expose radioBuffer.
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(2, adapterHal->rxPacketLengthReads);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_TRUE(adapter->receiving());
    assertAdapterRejectedRxWasCleanedUp();

    adapterHal->rxPacketLengthReads = 0;
    adapterHal->rxPacketLengthOverrideOccurrence = 0;
    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(2, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_HEX32(0x5678, adapterReceiver->packets[1].from);
    TEST_ASSERT_EQUAL_HEX32(0x87654321, adapterReceiver->packets[1].id);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
}

static void test_w12_adapter_checked_inner_zero_length_rejects_and_recovers()
{
    runW12CheckedInnerLengthRecovery(0);
}

static void test_w12_adapter_checked_inner_short_length_rejects_and_recovers()
{
    runW12CheckedInnerLengthRecovery(static_cast<uint16_t>(sizeof(PacketHeader) + 1));
}

// The outer receive IRQ check succeeds, then RadioLib's readData() performs its own raw IRQ
// status read. A command-status failure in that internal read must reject the frame and rearm RX
// without exposing the previously delivered radioBuffer as a duplicate.
static void test_w12_adapter_checked_internal_irq_status_failure_rejects_and_recovers()
{
    makeW12Adapter();
    prepareAdapterReception();

    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->badReceives());

    adapterHal->recording.transactions.clear();
    adapterHal->rawStatusReads = 0;
    adapterHal->failRawStatusOccurrence = 2;
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    // The first two raw status transactions are the outer validReceiveIrq() read and the
    // internal readData() read. Re-arm may perform another status observation, so only the
    // occurrence boundary is contractual here.
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(2, adapterHal->rawStatusReads);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_TRUE(adapter->receiving());
    assertAdapterRejectedRxWasCleanedUp();

    adapterHal->failRawStatusOccurrence = 0;
    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(2, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
}

// Cleanup must continue to CLEAR_IRQ when the shared FIFO cleanup itself reports an SPI command
// failure. The primary internal IRQ failure still rejects the frame and must not be replaced by
// an accidental FIFO read or stale delivery.
static void test_w12_adapter_internal_irq_failure_clears_irq_after_fifo_clear_failure()
{
    makeW12Adapter();
    prepareAdapterReception();

    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());

    adapterHal->recording.transactions.clear();
    adapterHal->rawStatusReads = 0;
    adapterHal->failRawStatusOccurrence = 2;
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO;
    adapterHal->failCommandOccurrence = 1;
    adapterHal->failCommandSeen = 0;
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(2, adapterHal->rawStatusReads);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(1, adapterHal->failCommandSeen);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->badReceives());
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    assertAdapterRejectedRxWasCleanedUp();
}

static void test_w12_adapter_busy_tx_delay_preserves_incoming_reception()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapterHal->injectIrqAtRssiRead = 1;
    adapterHal->irqOnRssiRead = RADIOLIB_LR2021_IRQ_SYNCWORD_VALID;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(0, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_STANDBY)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_TX)));
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    assertAdapterReceptionDeliveredOnce();
}

static void test_w12_adapter_busy_tx_delay_preserves_rx_done_during_last_observation()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapterHal->injectIrqAtRssiRead = 3;
    adapterHal->irqOnRssiRead = RADIOLIB_LR2021_IRQ_RX_DONE;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(3, adapterHal->rssiReads);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(RADIOLIB_LR2021_IRQ_RX_DONE, adapterHal->irq);
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_STANDBY)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterReceptionDeliveredOnce();
}

static void test_w12_adapter_failed_observation_with_recovery_suppressed_preserves_rx_done()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapter->lastChipRecoveryMs = Time::getMillis();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_GET_RSSI_INST;
    adapterHal->injectIrqAtRssiRead = 1;
    adapterHal->irqOnRssiRead = RADIOLIB_LR2021_IRQ_RX_DONE;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(RADIOLIB_LR2021_IRQ_RX_DONE, adapterHal->irq);
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_FLRC_SYNCWORD)));
    adapterHal->failCommand = 0;
    assertAdapterReceptionDeliveredOnce();
}

static void test_w12_adapter_failed_observation_defers_fresh_recovery_until_rx_done_is_delivered()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_GET_RSSI_INST;
    adapterHal->injectIrqAtRssiRead = 1;
    adapterHal->irqOnRssiRead = RADIOLIB_LR2021_IRQ_RX_DONE;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(RADIOLIB_LR2021_IRQ_RX_DONE, adapterHal->irq);
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_FLRC_SYNCWORD)));
    adapterHal->failCommand = 0;
    assertAdapterReceptionDeliveredOnce();
}

static void test_w12_adapter_failed_observation_preserves_active_reception_and_later_completion()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_GET_RSSI_INST;
    adapterHal->injectIrqAtRssiRead = 1;
    adapterHal->irqOnRssiRead = RADIOLIB_LR2021_IRQ_SYNCWORD_VALID;
    // If another IRQ observation is made after the checked active snapshot, the frame completes in that read.
    adapterHal->injectIrqAtRead = 3;
    adapterHal->irqOnRead = RADIOLIB_LR2021_IRQ_RX_DONE;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_FLRC_SYNCWORD)));
    adapterHal->failCommand = 0;
    adapterHal->injectIrqAtRead = 0;
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    assertAdapterReceptionDeliveredOnce();
}

#if defined(MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX) && MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX
// Exercise the production queue, scripted chip, IRQ completion and descriptor ownership together.
static void test_w12_adapter_tx_attempt_tracks_queue_start_done_and_pool_reuse()
{
    makeW12Adapter();
    // FLRC's passive channel scan needs idle RX armed before it can grant TX.
    RadioInterface::TxAttempt attempt;
    auto *packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->trackTx(attempt, packet));
    TEST_ASSERT_FALSE(adapter->trackTx(attempt, packet));
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Queued, (int)adapter->getTxStatus(attempt).state);
    TEST_ASSERT_TRUE(adapter->queueTransmission(packet));
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Transmitting, (int)adapter->getTxStatus(attempt).state);
    const auto generation = adapter->getTxStatus(attempt).generation;
    Time::advanceTestMillis(7);
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->transmitInterrupt();
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Sent, (int)adapter->getTxStatus(attempt).state);
    TEST_ASSERT_EQUAL_UINT32(Time::getMillis(), adapter->getTxStatus(attempt).completedAtMsec);

    packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->trackTx(attempt, packet));
    adapter->notifyTxFinished(packet, RadioInterface::TxState::Sent, generation);
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Queued, (int)adapter->getTxStatus(attempt).state);
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_TX;
    TEST_ASSERT_FALSE(adapter->sendNow(packet));
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Failed, (int)adapter->getTxStatus(attempt).state);
    packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->trackTx(attempt, packet));
    adapterHal->failCommand = 0;
    TEST_ASSERT_TRUE(adapter->sendNow(packet));
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TIMEOUT;
    adapter->transmitInterrupt();
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Failed, (int)adapter->getTxStatus(attempt).state);
}

static void test_w12_adapter_forced_standby_cannot_start_ack_wait()
{
    makeW12Adapter();
    adapter->stop();
    RadioInterface::TxAttempt attempt;
    auto *packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->trackTx(attempt, packet));
    TEST_ASSERT_TRUE(adapter->sendNow(packet));
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Transmitting, (int)adapter->getTxStatus(attempt).state);
    adapter->stop();
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Failed, (int)adapter->getTxStatus(attempt).state);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());

    packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->trackTx(attempt, packet));
    TEST_ASSERT_TRUE(adapter->sendNow(packet));
    adapter->stopViaLoRaBase();
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Failed, (int)adapter->getTxStatus(attempt).state);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());

    packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->trackTx(attempt, packet));
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    TEST_ASSERT_TRUE(adapter->sendNow(packet));
    adapter->stop();
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Sent, (int)adapter->getTxStatus(attempt).state);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->goodTransmits());
}

static void test_w12_adapter_production_queue_eviction_reject_cancel_and_no_lora()
{
    makeW12Adapter();
    adapter->stop();
    RadioInterface::TxAttempt attempts[MAX_TX_QUEUE + 2];
    meshtastic_MeshPacket *packets[MAX_TX_QUEUE + 2] = {};
    for (unsigned i = 0; i < MAX_TX_QUEUE; ++i) {
        packets[i] = makeAdapterTransmission();
        packets[i]->id = i + 1;
        packets[i]->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
        TEST_ASSERT_TRUE(adapter->trackTx(attempts[i], packets[i]));
        TEST_ASSERT_EQUAL_INT(ERRNO_OK, adapter->send(packets[i]));
    }
    packets[MAX_TX_QUEUE] = makeAdapterTransmission();
    packets[MAX_TX_QUEUE]->id = MAX_TX_QUEUE + 1;
    packets[MAX_TX_QUEUE]->priority = meshtastic_MeshPacket_Priority_ACK;
    TEST_ASSERT_TRUE(adapter->trackTx(attempts[MAX_TX_QUEUE], packets[MAX_TX_QUEUE]));
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, adapter->send(packets[MAX_TX_QUEUE]));
    unsigned dropped = 0;
    for (unsigned i = 0; i < MAX_TX_QUEUE; ++i)
        dropped += adapter->getTxStatus(attempts[i]).state == RadioInterface::TxState::Dropped;
    TEST_ASSERT_EQUAL_UINT32(1, dropped);
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Queued, (int)adapter->getTxStatus(attempts[MAX_TX_QUEUE]).state);
    packets[MAX_TX_QUEUE + 1] = makeAdapterTransmission();
    packets[MAX_TX_QUEUE + 1]->id = MAX_TX_QUEUE + 2;
    packets[MAX_TX_QUEUE + 1]->priority = meshtastic_MeshPacket_Priority_BACKGROUND;
    TEST_ASSERT_TRUE(adapter->trackTx(attempts[MAX_TX_QUEUE + 1], packets[MAX_TX_QUEUE + 1]));
    TEST_ASSERT_NOT_EQUAL(ERRNO_OK, adapter->send(packets[MAX_TX_QUEUE + 1]));
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Rejected, (int)adapter->getTxStatus(attempts[MAX_TX_QUEUE + 1]).state);
    TEST_ASSERT_TRUE(adapter->cancelSending(packets[MAX_TX_QUEUE]->from, MAX_TX_QUEUE + 1));
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Cancelled, (int)adapter->getTxStatus(attempts[MAX_TX_QUEUE]).state);
    adapter->releaseQueuedTransmissions();

    auto *packet = makeAdapterTransmission();
    packet->to = NODENUM_BROADCAST_NO_LORA;
    TEST_ASSERT_TRUE(adapter->trackTx(attempts[0], packet));
    TEST_ASSERT_EQUAL_INT(ERRNO_SHOULD_RELEASE, adapter->send(packet));
    TEST_ASSERT_EQUAL_INT((int)RadioInterface::TxState::Rejected, (int)adapter->getTxStatus(attempts[0]).state);
    packetPool.release(packet);
}

// A chip finishing SET_TX before its return must complete from the real queued notification,
// without waiting for the 100ms timeout or calling a transmit handler directly.
static void test_w12_adapter_short_send_arms_irq_before_set_tx_and_completes_immediately()
{
    makeW12Adapter();
    adapter->stop();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TIMEOUT;
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    const auto liveBefore = packetPoolLiveBytes();
    const uint32_t startedAt = Time::getMillis();
    TEST_ASSERT_TRUE(adapter->sendNow(makeAdapterTransmission()));
    TEST_ASSERT_TRUE(adapterHal->interruptArmedAtSetTx);
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_TX)));
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(startedAt, Time::getMillis());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(0, adapter->droppedTransmits());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapter->goodTransmits());
}

static void test_w12_adapter_send_without_tx_done_times_out_and_releases_packet_once()
{
    makeW12Adapter();
    adapter->stop();
    const auto liveBefore = packetPoolLiveBytes();
    TEST_ASSERT_TRUE(adapter->sendNow(makeAdapterTransmission()));
    Time::advanceTestMillis(W12FlrcProfile::TX_TIMEOUT_MS - 1);
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    Time::advanceTestMillis(1);
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(1, adapter->droppedTransmits());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT16(1, adapter->droppedTransmits());
}

static void test_w12_adapter_failed_irq_status_cannot_credit_stale_tx_done()
{
    makeW12Adapter();
    adapter->stop();
    const auto liveBefore = packetPoolLiveBytes();
    TEST_ASSERT_TRUE(adapter->sendNow(makeAdapterTransmission()));
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapterHal->rawStatusFailed = true;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(1, adapter->droppedTransmits());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
    adapterHal->rawStatusFailed = false;
    adapter->armReceive();
#if MESHTASTIC_W12_BENCHMARK_ATOMIC_FLRC_CONSUME && RADIOLIB_SPI_PARANOID
    // Failed full profile recovery cannot be bypassed by merely arming RX.
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_TRUE(adapter->recover());
    adapter->armReceive();
#endif
    TEST_ASSERT_TRUE(adapter->receiving());
}

static void test_w12_adapter_terminal_send_error_and_start_failure_release_without_success()
{
    makeW12Adapter();
    adapter->stop();
    const auto liveBefore = packetPoolLiveBytes();
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TIMEOUT;
    TEST_ASSERT_TRUE(adapter->sendNow(makeAdapterTransmission()));
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(1, adapter->droppedTransmits());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
    TEST_ASSERT_GREATER_THAN_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();
    adapter->stop();
    adapterHal->irqOnSetTx = 0;
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_TX;
    TEST_ASSERT_FALSE(adapter->sendNow(makeAdapterTransmission()));
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(2, adapter->droppedTransmits());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
    TEST_ASSERT_GREATER_THAN_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    assertAdapterSetRxTimeout();
}

#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
// Drive four packets from the real W12 owner loop through Router/MeshService,
// then deliver the production RadioLib ISR_TX and guarded notifications. This
// is intentionally separate from the counter wire seam: ownsTx(pointer, id),
// queue dequeue, TX_DONE validation, and pool release all participate here.
static void test_w12_burst_production_four_frame_sequence_counts_and_rearms()
{
    makeW12BurstOwnerFixture();
    const auto liveBefore = packetPoolLiveBytes();
    for (unsigned i = 0; i < 4; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    TEST_ASSERT_EQUAL_UINT32(4, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(4, adapterDiagnostics->getStats().enqueued);
    const auto *first = adapter->frontForTest();
    TEST_ASSERT_NOT_NULL(first);
    TEST_ASSERT_TRUE(adapterDiagnostics->ownsTx(first));

    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    const auto rxBeforeFirst = adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX));
    adapter->serviceNotifications(); // ordinary timer, CCA, and first SET_TX
    TEST_ASSERT_TRUE(adapter->isSending());

    for (unsigned frame = 1; frame <= 4; ++frame) {
        adapter->serviceNotifications(); // confirmed TX_DONE through ISR_TX
        if (frame < 4) {
            TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
            const auto rxBeforeGuard = adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX));
            adapter->serviceNotifications(); // dedicated guarded event starts the next frame
            TEST_ASSERT_TRUE(adapter->isSending());
            TEST_ASSERT_EQUAL_UINT32(rxBeforeGuard, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
        } else {
            TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
        }
    }

    const auto diagnostics = adapterDiagnostics->getPreSendAttributionDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.burstCount);
    TEST_ASSERT_EQUAL_UINT32(3, diagnostics.burstArmed);
    TEST_ASSERT_EQUAL_UINT32(4, diagnostics.burstFrames);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.burstAborted);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::SNAPSHOT_PRE_SEND_ATTRIBUTION)));
    const auto wire = takeAdapterPreSendAttributionReply();
    TEST_ASSERT_EQUAL_UINT32(3, adapterPreSendU32(wire, 114));
    TEST_ASSERT_EQUAL_UINT32(4, adapterPreSendU32(wire, 118));
    TEST_ASSERT_EQUAL_UINT32(0, adapterPreSendU32(wire, 122));
    TEST_ASSERT_EQUAL_UINT32(1, adapterPreSendU32(wire, 126));
    TEST_ASSERT_EQUAL_UINT32(4, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(4, adapterDiagnostics->getDiagnostics().txTerminal);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_GREATER_THAN_UINT32(rxBeforeFirst, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    const auto phaseTiming = diagnostics.phaseTiming;
    TEST_ASSERT_TRUE(phaseTiming.available);
    TEST_ASSERT_EQUAL_UINT32(4, phaseTiming.producerSendToMeshUs.count);
    TEST_ASSERT_TRUE(phaseTiming.pkiCcmAvailable);
    TEST_ASSERT_EQUAL_UINT32(4, phaseTiming.pkiCcmEncodeUs.count);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(phaseTiming.producerSendToMeshUs.max, phaseTiming.producerSendToMeshUs.sum);
    TEST_ASSERT_EQUAL_UINT32(3, phaseTiming.burstPrepareUs.count);
    TEST_ASSERT_EQUAL_UINT32(3, phaseTiming.burstPrepareSuccesses);
    TEST_ASSERT_EQUAL_UINT32(0, phaseTiming.burstPrepareFailures);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(phaseTiming.burstPrepareUs.max, phaseTiming.burstPrepareUs.sum);
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(3, phaseTiming.burstGuardLateMs.count);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(phaseTiming.burstGuardLateMs.max, phaseTiming.burstGuardLateMs.sum);
    TEST_ASSERT_EQUAL_UINT32(0, phaseTiming.failedTxCount);
#endif
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
}

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
// The production Router auth gate receives the actual encrypted packet emitted by MeshService.
// This proves the decode timer is around perhapsDecode and remains gated by the exact W12 identity,
// rather than being a counter-only call or a timer around arbitrary decoded input.
static void test_w12_burst_production_router_auth_gate_records_rx_decode()
{
    makeW12BurstOwnerFixture();
    TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    auto *queued = adapter->frontForTest();
    TEST_ASSERT_NOT_NULL(queued);
    TEST_ASSERT_EQUAL_UINT8(meshtastic_MeshPacket_encrypted_tag, queued->which_payload_variant);
    TEST_ASSERT_TRUE(queued->pki_encrypted);

    meshtastic_MeshPacket received = *queued;
    received.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    received.via_mqtt = false;
    myNodeInfo.my_node_num = adapterBurstDestination;
    crypto->setDHPrivateKey(adapterBurstDestinationPrivateKey);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(passesRoutingAuthGate(&received)));

    const auto diagnostics = adapterDiagnostics->getPreSendAttributionDiagnostics();
    TEST_ASSERT_TRUE(diagnostics.phaseTiming.available);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.phaseTiming.rxGateDecodeUs.count);
    TEST_ASSERT_TRUE(diagnostics.phaseTiming.pkiCcmAvailable);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.phaseTiming.pkiCcmEncodeUs.count);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.phaseTiming.pkiCcmDecodeUs.count);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(diagnostics.phaseTiming.rxGateDecodeUs.max, diagnostics.phaseTiming.rxGateDecodeUs.sum);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.phaseTiming.failedTxCount);
}
#endif

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
static void test_w12_burst_owned_irq_failure_records_validation_stage_without_invented_result()
{
    makeW12BurstOwnerFixture();
    TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    const PacketId failedId = adapter->frontForTest()->id;
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TIMEOUT;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getStats().txFailures);
    const auto failed = adapterDiagnostics->getPreSendAttributionDiagnostics().phaseTiming;
    TEST_ASSERT_EQUAL_UINT32(1, failed.failedTxCount);
    TEST_ASSERT_EQUAL_UINT32(failedId, failed.failedTxLastPacketId);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::TxFailureStage::TX_IRQ), failed.failedTxLastStage);
    TEST_ASSERT_EQUAL_INT16(INT16_MIN, failed.failedTxLastRadioResult);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
}

static void test_w12_burst_owned_start_failure_records_exact_stage_and_success_keeps_summary()
{
    makeW12BurstOwnerFixture();
    TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    const PacketId failedId = adapter->frontForTest()->id;
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_TX;
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getStats().txFailures);
    auto failed = adapterDiagnostics->getPreSendAttributionDiagnostics().phaseTiming;
    TEST_ASSERT_EQUAL_UINT32(1, failed.failedTxCount);
    TEST_ASSERT_EQUAL_UINT32(failedId, failed.failedTxLastPacketId);
    TEST_ASSERT_EQUAL_UINT32(0, failed.failedTxLastSequence);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::TxFailureStage::START_TRANSMIT), failed.failedTxLastStage);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_SPI_CMD_INVALID, failed.failedTxLastRadioResult);

    adapterHal->failCommand = 0;
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getStats().txSucceeded);
    const auto after = adapterDiagnostics->getPreSendAttributionDiagnostics().phaseTiming;
    TEST_ASSERT_EQUAL_UINT32(1, after.failedTxCount);
    TEST_ASSERT_EQUAL_UINT32(failedId, after.failedTxLastPacketId);
    TEST_ASSERT_EQUAL_UINT8(failed.failedTxLastStage, after.failedTxLastStage);
    TEST_ASSERT_EQUAL_INT16(failed.failedTxLastRadioResult, after.failedTxLastRadioResult);
}

// Two admitted owner packets must use the real RadioLib TX_DONE poll/notification path. The
// second frame is drained by STOP, so its completion is observed before the owner slot releases.
static void test_w12_burst_owner_gap_pairs_real_tx_done_with_next_start_and_drains_stop()
{
    makeW12BurstOwnerFixture();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());

    adapterHal->irqOnSetTx = 0;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());

    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications(); // The production poll discovers TX_DONE.
    adapter->serviceNotifications(); // The production ISR_TX notification completes frame one.
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());

    adapter->serviceNotifications(); // The guarded owner handoff starts frame two.
    TEST_ASSERT_TRUE(adapter->isSending());

    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::STOP)));
    adapter->stop(); // Standby drains the pending poll and its ISR_TX before forced completion.

    const auto gaps = adapterDiagnostics->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, gaps.ownerTxNotifyToStartTransmitCallUs.count);
    TEST_ASSERT_EQUAL_UINT32(2, gaps.txValidDone);
    TEST_ASSERT_EQUAL_UINT32(1, gaps.txUnpaired);
    TEST_ASSERT_EQUAL_UINT32(0, gaps.txStartFailures);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_FALSE(adapter->isSending());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::SNAPSHOT_RADIO_GAPS)));
    const auto wire = takeAdapterRadioGapsReply();
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::OWNER_RADIO_GAPS), wire.bytes[3]);
    TEST_ASSERT_EQUAL_UINT32(1, adapterRadioGapsU32(wire, 44));
    TEST_ASSERT_EQUAL_UINT32(2, adapterRadioGapsU32(wire, 80));
    TEST_ASSERT_EQUAL_UINT32(1, adapterRadioGapsU32(wire, 92));
}

// A SET_TX failure after a completed owner frame must consume the pending pairing attempt as a
// failed start and leave the successful TX gap metric empty.
static void test_w12_burst_owner_gap_failed_set_tx_after_completion_has_no_pair()
{
    makeW12BurstOwnerFixture();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());

    adapterHal->irqOnSetTx = 0;
    adapter->serviceNotifications();
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());

    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_TX;
    adapter->serviceNotifications(); // The guarded handoff reaches the real startTransmit call.
    TEST_ASSERT_FALSE(adapter->isSending());

    const auto gaps = adapterDiagnostics->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, gaps.txValidDone);
    TEST_ASSERT_EQUAL_UINT32(1, gaps.txStartFailures);
    TEST_ASSERT_EQUAL_UINT32(0, gaps.ownerTxNotifyToStartTransmitCallUs.count);
    TEST_ASSERT_EQUAL_UINT32(0, gaps.txUnpaired);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::STOP)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::SNAPSHOT_RADIO_GAPS)));
    const auto wire = takeAdapterRadioGapsReply();
    TEST_ASSERT_EQUAL_UINT32(1, adapterRadioGapsU32(wire, 88));
    TEST_ASSERT_EQUAL_UINT32(0, adapterRadioGapsU32(wire, 44));
}

// STOP may complete a producer window while an owner packet remains queued. Cancelling that
// packet must freeze the page, and a later stale ISR_TX notification must not touch its slot.
static void test_w12_burst_owner_gap_stop_cancel_freezes_after_stale_tx_notification()
{
    makeW12BurstOwnerFixture();
    const auto liveBefore = packetPoolLiveBytes();
    TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::STOP)));
    adapter->releaseQueuedTransmissions();
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());

    const auto frozen = adapterDiagnostics->getRadioGapDiagnostics();
    TEST_ASSERT_TRUE(adapter->queueTxNotificationForTest());
    adapter->serviceNotifications();
    const auto after = adapterDiagnostics->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(frozen.rxNotifications, after.rxNotifications);
    TEST_ASSERT_EQUAL_UINT32(frozen.txValidDone, after.txValidDone);
    TEST_ASSERT_EQUAL_UINT32(frozen.txUnpaired, after.txUnpaired);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::SNAPSHOT_RADIO_GAPS)));
    const auto wire = takeAdapterRadioGapsReply();
    TEST_ASSERT_EQUAL_UINT8(0, wire.bytes[21]);
    TEST_ASSERT_EQUAL_UINT32(0, adapterRadioGapsU32(wire, 80));
    TEST_ASSERT_EQUAL_UINT32(0, adapterRadioGapsU32(wire, 92));
}
#endif

// Use a real W12 owner slot while TX_DONE is already pending, then enter the
// LR2021 standby path. The drain must complete the packet under the
// suppression guard and must leave the second owner packet queued.
static void test_w12_burst_production_pending_tx_done_standby_does_not_arm()
{
    makeW12BurstOwnerFixture();
    const auto liveBefore = packetPoolLiveBytes();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    TEST_ASSERT_EQUAL_UINT32(2, adapter->packetsInTxQueue());
    // Let the production software poll discover TX_DONE after SET_TX. The poll
    // notification is the one standby must drain under burst suppression.
    adapterHal->irqOnSetTx = 0;
    adapter->serviceNotifications(); // ordinary timer starts TX and queues ISR_POLL_TICK
    TEST_ASSERT_TRUE(adapter->isSending());
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;

    adapter->stop(); // production standby drains poll -> ISR_TX
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(0, adapterDiagnostics->getStats().txFailures);
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getDiagnostics().txTerminal);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    const auto burstDiagnostics = adapterDiagnostics->getPreSendAttributionDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(0, burstDiagnostics.burstArmed);
    TEST_ASSERT_EQUAL_UINT32(0, burstDiagnostics.burstFrames);

    // A completion latched after standby is also stale. It must be consumed
    // without reconstructing RX or an ordinary TX timer around a null packet.
    TEST_ASSERT_TRUE(adapter->queueTxNotificationForTest());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());

    // No guarded event or ordinary replacement timer may wake standby and
    // transmit the second owner packet. Release it through the normal queue
    // cancellation path so the owner slot and pool are both accounted for.
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->releaseQueuedTransmissions();
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
}

// Reconfigure while frame two is physically in flight. Its guard has already
// been consumed, so there is no stale dedicated event available to restart the
// queue. Reconfigure must therefore schedule the ordinary timer after RX is
// armed, and the failed in-flight owner must not strand frames three and four.
static void test_w12_burst_production_reconfigure_inflight_frame_resumes_ordinary_queue()
{
    makeW12BurstOwnerFixture();
    for (unsigned i = 0; i < 4; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());

    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications(); // ordinary timer starts frame one
    adapter->serviceNotifications(); // ISR_TX arms the first guard
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());

    // Consume the guard and start frame two without TX_DONE. Reconfigure now
    // sees active=true and timerPending=false, with an ISR_POLL_TICK pending.
    adapterHal->irqOnSetTx = 0;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    const PacketId failedPacketId = adapter->sendingForTest()->id;
    TEST_ASSERT_TRUE(adapter->reconfigureForTest());
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getStats().txFailures);
    TEST_ASSERT_EQUAL_UINT32(2, adapter->packetsInTxQueue());

    // The ordinary timer created after RX rearm must drive frame three. Its
    // completion may start a fresh bounded sequence for frame four, which is
    // still checked through the production guarded notification path.
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(3, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(4, adapterDiagnostics->getDiagnostics().txTerminal);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    const auto phaseTiming = adapterDiagnostics->getPreSendAttributionDiagnostics().phaseTiming;
    TEST_ASSERT_EQUAL_UINT32(1, phaseTiming.failedTxCount);
    TEST_ASSERT_EQUAL_UINT32(failedPacketId, phaseTiming.failedTxLastPacketId);
    TEST_ASSERT_EQUAL_UINT32(1, phaseTiming.failedTxLastSequence);
    TEST_ASSERT_NOT_EQUAL_UINT32(0, phaseTiming.failedTxLastAtMs);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::TxFailureStage::FORCED_COMPLETE_FALSE),
                            phaseTiming.failedTxLastStage);
    TEST_ASSERT_EQUAL_INT16(RADIOLIB_ERR_NONE, phaseTiming.failedTxLastRadioResult);
#endif
}

// An ISR_TX notification can overwrite the single guarded notification slot
// after the previous frame has already released sendingPacket. The null-packet
// path must recover the ordinary handoff when that displaced event represented
// a live burst, including the reconfigure and STOP stale-event markers. An
// explicit standby case remains inert.
static void test_w12_burst_null_tx_overwrite_restores_live_handoffs()
{
    makeW12BurstOwnerFixture();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_TRUE(adapter->queueTxNotificationForTest());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
    deleteW12Adapter();

    makeW12BurstOwnerFixture();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_TRUE(adapter->reconfigureForTest());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_TRUE(adapter->queueTxNotificationForTest());
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
    deleteW12Adapter();

    makeW12BurstOwnerFixture();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::STOP)));
    TEST_ASSERT_TRUE(adapter->queueTxNotificationForTest());
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
}

// A late ISR_TX can also overwrite an ordinary timer with no burst state at
// all. The real unowned queue must retain its normal timer and complete the
// second packet through the ordinary path.
static void test_w12_burst_null_tx_overwrite_restores_ordinary_timer()
{
    makeW12Adapter();
    adapter->stop();
    adapter->armReceive();
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    TEST_ASSERT_TRUE(adapter->queueTransmission(makeAdapterTransmission()));
    TEST_ASSERT_TRUE(adapter->queueOnlyForTest(makeAdapterTransmission()));

    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());

    TEST_ASSERT_TRUE(adapter->queueTxNotificationForTest());
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(2, adapter->goodTransmits());
}

// End the real owner window during frame two of a burst. Physical completion remains
// owned by the TX IRQ, while already-admitted packets drain without another burst guard.
static void assertW12BurstRunEndDrainsActiveTransmission(bool deadline)
{
    makeW12BurstOwnerFixture();
    const auto liveBefore = packetPoolLiveBytes();
    for (unsigned i = 0; i < 3; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications(); // frame one completes and arms the burst guard
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    adapterHal->irqOnSetTx = 0;
    adapter->serviceNotifications(); // frame two is physically active, without a completion IRQ
    TEST_ASSERT_TRUE(adapter->isSending());
    const auto *activePacket = adapter->sendingForTest();
    const auto rxArms = adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX));
    if (deadline) {
        Time::advanceTestMillis(adapterBurstRun().durationMs + 1);
        adapterDiagnostics->runOnce();
    } else {
        TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                              static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::STOP)));
    }

    TEST_ASSERT_FALSE(adapterDiagnostics->getStats().running);
    TEST_ASSERT_TRUE(adapterDiagnostics->getStats().complete);
    TEST_ASSERT_TRUE(adapter->isSending());
    TEST_ASSERT_EQUAL_PTR(activePacket, adapter->sendingForTest());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(rxArms, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterDiagnostics->getStats().txFailures);
    const auto guardsAtStop = adapterDiagnostics->getPreSendAttributionDiagnostics().burstArmed;

    // The normal completion path owns the current frame and returns to RX. The remaining
    // admitted frame then drains through normal scheduling, without extending the burst.
    adapterHal->irq = RADIOLIB_LR2021_IRQ_TX_DONE;
    TEST_ASSERT_TRUE(adapter->queueTxNotificationForTest());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    for (unsigned i = 0; i < 8 && adapterDiagnostics->getStats().txSucceeded < 3; ++i)
        adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(3, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(0, adapterDiagnostics->getStats().txFailures);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(guardsAtStop, adapterDiagnostics->getPreSendAttributionDiagnostics().burstArmed);
    TEST_ASSERT_EQUAL_UINT32(3, adapterDiagnostics->getDiagnostics().txTerminal);
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
}

static void test_w12_burst_stop_drains_active_transmission_before_normal_queue()
{
    assertW12BurstRunEndDrainsActiveTransmission(false);
}

static void test_w12_burst_deadline_drains_active_transmission_before_normal_queue()
{
    assertW12BurstRunEndDrainsActiveTransmission(true);
}

// STOP/deadline aborts clear the in-memory burst state before the one-slot
// guarded event can be cancelled. Its stale dispatch must repair the ordinary
// timer, while explicit standby must consume the same stale event without
// waking the radio.
static void test_w12_burst_stop_and_standby_stale_events_preserve_normal_send()
{
    makeW12BurstOwnerFixture();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications(); // ordinary timer starts frame one
    adapter->serviceNotifications(); // ISR_TX arms the guarded event
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::STOP)));
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());

    // The abort-owned stale event restores the ordinary timer and sends the
    // queued packet through the normal lifecycle.
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());

    // Recreate a pending guarded event with a fresh run, then finish it by
    // deadline. The stale event must restore the ordinary timer so the queued
    // packet is not stranded.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::RESET)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::START)));
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    Time::advanceTestMillis(adapterBurstRun().durationMs + TestableW12Adapter::burstGuardMsForTest() + 1);
    adapterDiagnostics->runOnce();
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->serviceNotifications(); // consume stale event and restore normal timer
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());

    // A third run takes explicit standby with a pending guard. The stale event
    // must not wake the radio or dequeue the packet; a later explicit RX arm
    // and ordinary timer remain usable.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::RESET)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendAdapterBurstControl(W12BenchmarkModule::Op::START)));
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    adapter->stop();
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->serviceNotifications(); // consume stale event; standby remains inert
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->receiving());

    adapter->armReceive();
    adapter->armOrdinaryTimerForTest();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
}

class BurstDraftTxHook : public RadioTxHook
{
  public:
    explicit BurstDraftTxHook(PreTxAction result) : result(result) {}

    PreTxAction beforeTransmit(RadioInterface *, meshtastic_MeshPacket *) override { return result; }
    void packetReleased(RadioInterface *, const meshtastic_MeshPacket *) override { released++; }

    PreTxAction result;
    unsigned released = 0;
};

class StandbyReconfigureTxHook : public RadioTxHook
{
  public:
    PreTxAction beforeTransmit(RadioInterface *, meshtastic_MeshPacket *) override { return RadioTxHook::PRETX_SEND; }
    void packetReleased(RadioInterface *, const meshtastic_MeshPacket *) override
    {
        ++released;
        if (!reconfigured && adapter)
            reconfigured = adapter->reconfigureForTest();
    }

    bool reconfigured = false;
    unsigned released = 0;
};

// A release hook may reconfigure the radio while explicit standby is still
// unwinding. The nested reconfigure must apply config without rearming RX or
// scheduling ordinary TX, and the caller must remain in standby until an
// explicit RX restart.
static void test_w12_burst_standby_release_hook_reconfigure_stays_standby()
{
    makeW12BurstOwnerFixture();
    const auto liveBefore = packetPoolLiveBytes();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = 0;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());

    auto *hook = new StandbyReconfigureTxHook();
    adapterOwnedTxHook = hook;
    adapter->stop();
    TEST_ASSERT_TRUE(hook->reconfigured);
    TEST_ASSERT_EQUAL_UINT32(1, hook->released);
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getStats().txFailures);
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());

    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());

    adapter->armReceive();
    adapter->armOrdinaryTimerForTest();
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(1, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getDiagnostics().txTerminal);
    TEST_ASSERT_EQUAL_UINT32(2, hook->released);
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
}

// The guarded event repeats the production pre-TX hook contract. Keep these
// real-HAL cases beside the adapter lifecycle tests so DROP and DEFER cannot
// regress into a dequeue or a double release while the draft is enabled.
static void test_w12_burst_pre_tx_defer_and_drop_preserve_hook_ownership()
{
    makeW12BurstOwnerFixture();
    const auto deferLiveBefore = packetPoolLiveBytes();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    auto *deferHook = new BurstDraftTxHook(RadioTxHook::PRETX_DEFER);
    adapterOwnedTxHook = deferHook;
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(0, deferHook->released);
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    adapter->releaseQueuedTransmissions();
    TEST_ASSERT_EQUAL_INT32(deferLiveBefore, packetPoolLiveBytes());
    deleteW12Adapter();

    makeW12BurstOwnerFixture();
    const auto dropLiveBefore = packetPoolLiveBytes();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    auto *dropHook = new BurstDraftTxHook(RadioTxHook::PRETX_DROP);
    adapterOwnedTxHook = dropHook;
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_UINT32(1, dropHook->released);
    TEST_ASSERT_EQUAL_INT32(dropLiveBefore, packetPoolLiveBytes());
}

// A TX_DONE may already be queued when a maintenance or STOP path enters standby.
// The real LR2021 standby drain must finish that notification while burst arming is
// suppressed, then leave the radio in standby without a second guarded event.
static void test_w12_burst_pending_tx_done_is_drained_without_rearming()
{
    makeW12Adapter();
    adapter->stop();
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    auto *packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->sendNow(packet));
    TEST_ASSERT_TRUE(adapter->isSending());

    adapter->stop();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->goodTransmits());
}

// Reconfigure cannot erase NotifiedWorkerThread's one pending slot. Drive a
// real owner guard through reconfigure, consume that stale event, and verify
// the queued second owner packet completes through the ordinary lifecycle.
static void test_w12_burst_reconfigure_consumes_stale_event_before_ordinary_send()
{
    makeW12BurstOwnerFixture();
    const auto liveBefore = packetPoolLiveBytes();
    for (unsigned i = 0; i < 2; ++i)
        TEST_ASSERT_EQUAL_INT(0, adapterDiagnostics->runOnce());
    adapterHal->irqOnSetTx = RADIOLIB_LR2021_IRQ_TX_DONE;
    adapter->serviceNotifications();
    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->burstTimerPendingForTest());
    TEST_ASSERT_TRUE(adapter->reconfigureForTest());
    TEST_ASSERT_FALSE(adapter->burstTimerPendingForTest());

    adapter->serviceNotifications(); // stale guard consumes and schedules ordinary TX
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());

    adapter->serviceNotifications();
    TEST_ASSERT_TRUE(adapter->isSending());
    adapter->serviceNotifications();
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_UINT32(2, adapterDiagnostics->getDiagnostics().txTerminal);
    TEST_ASSERT_EQUAL_UINT32(0, adapter->packetsInTxQueue());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
}

// A non-overwriting guarded notification must fail closed when the single
// notification slot is occupied. The queue remains owned by the ordinary path.
static void test_w12_burst_scheduler_rejection_keeps_packet_queued()
{
    makeW12Adapter();
    adapter->stop();
    auto *packet = makeAdapterTransmission();
    TEST_ASSERT_TRUE(adapter->queueOnlyForTest(packet));
    TEST_ASSERT_TRUE(adapter->queueOrdinaryNotificationForTest());
    TEST_ASSERT_FALSE(adapter->queueBurstNotificationForTest());
    TEST_ASSERT_EQUAL_UINT32(1, adapter->packetsInTxQueue());
    adapter->releaseQueuedTransmissions();
}
#endif
#else
static void test_w12_adapter_default_gate_refuses_flrc_send_and_releases_packet()
{
    makeW12Adapter();
    adapter->stop();
    const auto liveBefore = packetPoolLiveBytes();
    TEST_ASSERT_FALSE(adapter->sendNow(makeAdapterTransmission()));
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_TX)));
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
}
#endif

#if MESHTASTIC_W12_BENCHMARK_ATOMIC_FLRC_CONSUME && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) &&                   \
    ((defined(MESHTASTIC_W12_BENCHMARK_SINGLE_RX) && MESHTASTIC_W12_BENCHMARK_SINGLE_RX) ||                                      \
     defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS))
// Draft-only real adapter cases. They retain the current fixture and make the
// LR2021 Stat, Stat, Data FIFO offset and reply-phase failures observable.
static void configureAtomicFrame(uint32_t id, const uint8_t *payload, size_t payloadLength, uint8_t rssiAverageRaw,
                                 uint8_t rssiSyncRaw, uint8_t syncWord)
{
    PacketHeader header = {};
    header.from = 0x5678;
    header.to = NODENUM_BROADCAST;
    header.id = id;
    adapterHal->atomicPayload.resize(sizeof(header) + payloadLength);
    memcpy(adapterHal->atomicPayload.data(), &header, sizeof(header));
    memcpy(adapterHal->atomicPayload.data() + sizeof(header), payload, payloadLength);
    adapterHal->atomicPacketLength = adapterHal->atomicPayload.size();
    adapterHal->atomicRssiAverageRaw = rssiAverageRaw;
    adapterHal->atomicRssiSyncRaw = rssiSyncRaw;
    adapterHal->atomicSyncWord = syncWord;
}

static void test_w12_adapter_atomic_consume_two_finite_frames_refreshes_metadata()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapter->atomicConsumeForTest = true;
    adapterHal->atomicConsumeEnabled = true;
    adapterHal->atomicStatusMode = 0x01;
    adapterHal->rawStatusMode = 0x01;
    const uint8_t firstPayload[] = {0x42, 0x53, 0x64};
    configureAtomicFrame(0x87654321, firstPayload, sizeof(firstPayload), 0x50, 0x30, 0x10);

    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_HEX32(0x87654321, adapterReceiver->packets[0].id);
    TEST_ASSERT_EQUAL_UINT32(sizeof(firstPayload), adapterReceiver->packets[0].encrypted.size);
    TEST_ASSERT_TRUE(adapterReceiver->packets[0].has_rx_rssi);
    TEST_ASSERT_EQUAL_INT32(-80, adapterReceiver->packets[0].rx_rssi);

    adapterHal->recording.transactions.clear();
    const uint8_t secondPayload[] = {0xA0, 0xB0, 0xC0, 0xD0, 0xE0};
    configureAtomicFrame(0x10203040, secondPayload, sizeof(secondPayload), 0x64, 0x20, 0x20);
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    TEST_ASSERT_EQUAL_UINT32(2, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_HEX32(0x10203040, adapterReceiver->packets[1].id);
    TEST_ASSERT_NOT_EQUAL(adapterReceiver->packets[0].id, adapterReceiver->packets[1].id);
    TEST_ASSERT_EQUAL_UINT32(sizeof(secondPayload), adapterReceiver->packets[1].encrypted.size);
    TEST_ASSERT_EQUAL_INT32(-100, adapterReceiver->packets[1].rx_rssi);
    // One consume proof plus the existing full RX rearm modem query.
    TEST_ASSERT_EQUAL_UINT32(2, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_PACKET_TYPE)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_AND_CLEAR_IRQ_STATUS)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    TEST_ASSERT_TRUE(adapter->receiving());
}

static void test_w12_adapter_atomic_snapshot_command_timeout_stops_rearm()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapter->atomicConsumeForTest = true;
    adapterHal->atomicConsumeEnabled = true;
    adapterHal->atomicTimeoutSnapshotCommand = true;
    adapterHal->rawStatusMode = 0x01;
    adapterHal->recording.transactions.clear();

    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->atomicSnapshotCommandTimeouts);
    TEST_ASSERT_EQUAL_UINT32(0, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_TRUE(adapter->isOffline());
    adapterHal->recording.transactions.clear();
    adapter->armReceive();
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
}

static void test_w12_adapter_atomic_snapshot_nop_reply_failure_stops_rearm()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapter->atomicConsumeForTest = true;
    adapterHal->atomicConsumeEnabled = true;
    adapterHal->atomicFailSnapshotReply = true;
    adapterHal->rawStatusMode = 0x01;
    adapterHal->recording.transactions.clear();

    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    TEST_ASSERT_EQUAL_UINT32(0, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_TRUE(adapter->isOffline());
    adapterHal->recording.transactions.clear();
    adapter->armReceive();
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
}

static void test_w12_adapter_atomic_packet_status_and_fifo_reply_failures_rearm()
{
    for (const bool failPacketStatus : {true, false}) {
        makeW12Adapter();
        prepareAdapterReception();
        adapter->atomicConsumeForTest = true;
        adapterHal->atomicConsumeEnabled = true;
        adapterHal->rawStatusMode = 0x01;
        adapterHal->atomicFailPacketStatusReply = failPacketStatus;
        adapterHal->atomicFailFifoReply = !failPacketStatus;
        const uint8_t payload[] = {0x42, 0x53, 0x64};
        configureAtomicFrame(0x87654321, payload, sizeof(payload), 0x50, 0x30, 0x10);

        adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
        adapter->serviceNotifications();

        TEST_ASSERT_EQUAL_UINT32(0, adapterReceiver->packets.size());
        TEST_ASSERT_TRUE(adapter->receiving());
        TEST_ASSERT_FALSE(adapter->isOffline());
        TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS)));
        TEST_ASSERT_EQUAL_UINT32(failPacketStatus ? 0u : 1u, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    }
}

static void test_w12_adapter_atomic_foreign_modem_stays_offline_until_full_profile_restore()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapter->atomicConsumeForTest = true;
    adapterHal->packetTypeOverrideEnabled = true;
    adapterHal->packetTypeOverride = RADIOLIB_LR2021_PACKET_TYPE_LORA;
    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(0, adapterReceiver->packets.size());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_TRUE(adapter->isOffline());
    TEST_ASSERT_FALSE(RadioMode::status(config.lora).active_initialized);
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_AND_CLEAR_IRQ_STATUS)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)));

    adapterHal->recording.transactions.clear();
    adapter->armReceive();
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_FALSE(adapter->reconfigureForTest());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));

    // Only a successful full FLRC profile restore may clear the block. This is
    // deliberately separate from reconfigure/startReceive so cached mode does
    // not turn a foreign modem into an initialized receiver.
    adapterHal->packetTypeOverrideEnabled = false;
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_PACKET_TYPE;
    adapterHal->failCommandOccurrence = 1;
    adapterHal->failCommandSeen = 0;
    TEST_ASSERT_FALSE(adapter->recover());
    TEST_ASSERT_FALSE(RadioMode::status(config.lora).active_initialized);
    adapter->armReceive();
    TEST_ASSERT_FALSE(adapter->receiving());
    adapterHal->failCommand = 0;
    adapterHal->failCommandOccurrence = 0;
    TEST_ASSERT_TRUE(adapter->recover());
    TEST_ASSERT_TRUE(RadioMode::status(config.lora).active_initialized);
    adapter->armReceive();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_FALSE(adapter->isOffline());
    TEST_ASSERT_GREATER_THAN_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
}

static void test_w12_adapter_atomic_recovery_reproves_packet_type_before_discard()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapter->atomicConsumeForTest = true;
    adapterHal->atomicConsumeEnabled = true;
    adapterHal->atomicStatusMode = 0x01;
    adapterHal->rawStatusMode = 0x01;
    adapterHal->failRawStatusOccurrence = 1;
    adapterHal->atomicFailPacketTypeReply = true;
    adapterHal->atomicPacketTypeFailOccurrence = 2;
    const uint8_t payload[] = {0x42, 0x53, 0x64};
    configureAtomicFrame(0x87654321, payload, sizeof(payload), 0x50, 0x30, 0x10);

    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE);
    adapter->serviceNotifications();

    TEST_ASSERT_EQUAL_UINT32(0, adapterReceiver->packets.size());
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_TRUE(adapter->isOffline());
    TEST_ASSERT_EQUAL_UINT32(2, adapterHal->atomicPacketTypeReads);
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_GET_AND_CLEAR_IRQ_STATUS)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)));
    // The fresh type proof fails, so discardFlrcReceive must return before a
    // second snapshot or any foreign FIFO/IRQ cleanup.
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)));
}

static void test_w12_adapter_atomic_initial_full_restore_failure_blocks_ordinary_rearm()
{
    makeW12Adapter();
    adapter->stop();
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_PACKET_TYPE;
    adapterHal->failCommandOccurrence = 1;
    adapterHal->failCommandSeen = 0;
    TEST_ASSERT_FALSE(adapter->recover());
    adapterHal->recording.transactions.clear();
    adapter->armReceive();
    TEST_ASSERT_FALSE(adapter->receiving());
    TEST_ASSERT_TRUE(adapter->isOffline());
    TEST_ASSERT_FALSE(RadioMode::status(config.lora).active_initialized);
    TEST_ASSERT_EQUAL_UINT32(0, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_SET_RX)));
    TEST_ASSERT_FALSE(adapter->reconfigureForTest());
    adapterHal->failCommand = 0;
    adapterHal->failCommandOccurrence = 0;
    TEST_ASSERT_TRUE(adapter->recover());
    adapter->armReceive();
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_TRUE(RadioMode::status(config.lora).active_initialized);
}

// The generic LoRa branch must use the active FLRC snapshot in its historical
// region guard. A live UNSET edit must not accidentally block this snapshot's
// already-selected generic fallback read.
static void test_w12_adapter_lora_region_guard_uses_active_snapshot_on_live_mismatch()
{
    makeW12Adapter();
    prepareAdapterReception();
    adapter->stop();
    adapterHal->packetTypeOverrideEnabled = true;
    adapterHal->packetTypeOverride = RADIOLIB_LR2021_PACKET_TYPE_LORA;
    adapter->forceGenericReceive = true;
    const auto regionBefore = config.lora.region;
    config.lora.region = meshtastic_Config_LoRaConfig_RegionCode_UNSET;
    adapter->armReceive();
    adapterHal->recording.transactions.clear();
    adapterHal->signalReceive(RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_LORA_HEADER_VALID);
    adapter->serviceNotifications();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
    TEST_ASSERT_EQUAL_UINT32(1, adapterHal->recording.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)));
    config.lora.region = regionBefore;
}
#endif

static void runW12AdapterTests()
{
    RUN_TEST(test_w12_lr2021_implicit_cached_length_preserves_driver_reads);
    RUN_TEST(test_w12_lr2021_explicit_lora_prefix_preserves_driver_read);
    RUN_TEST(test_w12_lr2021_flrc_prefix_preserves_driver_read);
    RUN_TEST(test_w12_adapter_rx_arm_uses_configured_fallback_and_expected_timeout);
    RUN_TEST(test_w12_adapter_rx_arm_fifo_clear_is_opt_in);
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS)
    RUN_TEST(test_w12_adapter_finite_timeout_rejects_and_rearms);
#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
    RUN_TEST(test_w12_adapter_fifo_clear_failure_stays_offline_until_retry);
    RUN_TEST(test_w12_adapter_terminal_errors_rearm_fifo_without_reading_payload);
#endif
#endif
    RUN_TEST(test_w12_adapter_recovery_preserves_active_flrc_and_rearms_rx);
    RUN_TEST(test_w12_adapter_failed_rx_remains_offline_until_successful_rearm);
    RUN_TEST(test_w12_adapter_sensing_busy_and_failed_reads_defer_without_lora_cad);
    RUN_TEST(test_w12_adapter_terminal_rx_error_rejects_payload_and_rearms);
    RUN_TEST(test_w12_adapter_checked_rx_length_error_rejects_stale_buffer);
    RUN_TEST(test_w12_adapter_checked_inner_zero_length_rejects_and_recovers);
    RUN_TEST(test_w12_adapter_checked_inner_short_length_rejects_and_recovers);
    RUN_TEST(test_w12_adapter_checked_internal_irq_status_failure_rejects_and_recovers);
#if MESHTASTIC_W12_BENCHMARK_ATOMIC_FLRC_CONSUME && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) &&                   \
    ((defined(MESHTASTIC_W12_BENCHMARK_SINGLE_RX) && MESHTASTIC_W12_BENCHMARK_SINGLE_RX) ||                                      \
     defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS))
    RUN_TEST(test_w12_adapter_atomic_consume_two_finite_frames_refreshes_metadata);
    RUN_TEST(test_w12_adapter_atomic_snapshot_command_timeout_stops_rearm);
    RUN_TEST(test_w12_adapter_atomic_snapshot_nop_reply_failure_stops_rearm);
    RUN_TEST(test_w12_adapter_atomic_packet_status_and_fifo_reply_failures_rearm);
    RUN_TEST(test_w12_adapter_atomic_foreign_modem_stays_offline_until_full_profile_restore);
    RUN_TEST(test_w12_adapter_atomic_recovery_reproves_packet_type_before_discard);
    RUN_TEST(test_w12_adapter_atomic_initial_full_restore_failure_blocks_ordinary_rearm);
    RUN_TEST(test_w12_adapter_lora_region_guard_uses_active_snapshot_on_live_mismatch);
#endif
    RUN_TEST(test_w12_adapter_internal_irq_failure_clears_irq_after_fifo_clear_failure);
    RUN_TEST(test_w12_adapter_failed_irq_status_keeps_channel_busy_and_rejects_stale_rx);
    RUN_TEST(test_w12_adapter_transmit_requires_tx_done_and_never_double_completes);
    RUN_TEST(test_w12_adapter_disabling_queued_tx_restores_receive);
    RUN_TEST(test_w12_adapter_busy_tx_delay_preserves_incoming_reception);
    RUN_TEST(test_w12_adapter_busy_tx_delay_preserves_rx_done_during_last_observation);
    RUN_TEST(test_w12_adapter_failed_observation_with_recovery_suppressed_preserves_rx_done);
    RUN_TEST(test_w12_adapter_failed_observation_defers_fresh_recovery_until_rx_done_is_delivered);
    RUN_TEST(test_w12_adapter_failed_observation_preserves_active_reception_and_later_completion);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    RUN_TEST(test_w12_hal_metrics_saturate_and_preserve_zero_duration);
    RUN_TEST(test_w12_production_hal_virtual_transfer_and_yield_are_counted);
    RUN_TEST(test_w12_production_hal_controls_collect_end_to_end);
    RUN_TEST(test_w12_production_hal_detach_and_reattach_does_not_use_freed_metrics);
#endif
    RUN_TEST(test_w12_adapter_rx_liveness_snapshot_reads_stats_irq_and_rssi_once);
    RUN_TEST(test_w12_adapter_pre_send_snapshot_reads_raw_rx_state_without_clearing);
    RUN_TEST(test_w12_adapter_active_rx_failure_is_classified_by_one_irq_read);
    RUN_TEST(test_w12_adapter_rx_liveness_snapshot_reports_chip_stats_failure);
    RUN_TEST(test_w12_adapter_rx_liveness_snapshot_reports_irq_status_failure);
    RUN_TEST(test_w12_adapter_rx_liveness_snapshot_reports_rssi_failure);
    RUN_TEST(test_w12_adapter_rx_liveness_rearms_once_and_guards_active_or_queued_tx);
    RUN_TEST(test_w12_adapter_rx_liveness_does_not_add_stats_or_rssi_reads_to_receive_isr);
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_successful_arm_stages);
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_standby_failure_and_result);
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_start_failure_retry_and_result);
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_irq_map_failure_and_result);
    RUN_TEST(test_w12_adapter_radio_diagnostics_poll_reads_raw_status_once);
    RUN_TEST(test_w12_adapter_radio_diagnostic_software_irq_state_tracks_standby_and_rx);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    RUN_TEST(test_w12_adapter_owner_gap_rx_done_notification_records_rearm);
    RUN_TEST(test_w12_adapter_owner_gap_rx_rearm_failure_is_invalid_without_sample);
#endif
#endif
#if defined(MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX) && MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX
    RUN_TEST(test_w12_adapter_tx_attempt_tracks_queue_start_done_and_pool_reuse);
    RUN_TEST(test_w12_adapter_production_queue_eviction_reject_cancel_and_no_lora);
    RUN_TEST(test_w12_adapter_forced_standby_cannot_start_ack_wait);
    RUN_TEST(test_w12_adapter_short_send_arms_irq_before_set_tx_and_completes_immediately);
    RUN_TEST(test_w12_adapter_send_without_tx_done_times_out_and_releases_packet_once);
    RUN_TEST(test_w12_adapter_failed_irq_status_cannot_credit_stale_tx_done);
    RUN_TEST(test_w12_adapter_terminal_send_error_and_start_failure_release_without_success);
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
    RUN_TEST(test_w12_burst_production_four_frame_sequence_counts_and_rearms);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    RUN_TEST(test_w12_burst_production_router_auth_gate_records_rx_decode);
    RUN_TEST(test_w12_burst_owned_start_failure_records_exact_stage_and_success_keeps_summary);
    RUN_TEST(test_w12_burst_owned_irq_failure_records_validation_stage_without_invented_result);
    RUN_TEST(test_w12_burst_owner_gap_pairs_real_tx_done_with_next_start_and_drains_stop);
    RUN_TEST(test_w12_burst_owner_gap_failed_set_tx_after_completion_has_no_pair);
    RUN_TEST(test_w12_burst_owner_gap_stop_cancel_freezes_after_stale_tx_notification);
#endif
    RUN_TEST(test_w12_burst_production_pending_tx_done_standby_does_not_arm);
    RUN_TEST(test_w12_burst_production_reconfigure_inflight_frame_resumes_ordinary_queue);
    RUN_TEST(test_w12_burst_null_tx_overwrite_restores_live_handoffs);
    RUN_TEST(test_w12_burst_null_tx_overwrite_restores_ordinary_timer);
    RUN_TEST(test_w12_burst_standby_release_hook_reconfigure_stays_standby);
    RUN_TEST(test_w12_burst_stop_and_standby_stale_events_preserve_normal_send);
    RUN_TEST(test_w12_burst_stop_drains_active_transmission_before_normal_queue);
    RUN_TEST(test_w12_burst_deadline_drains_active_transmission_before_normal_queue);
    RUN_TEST(test_w12_burst_pre_tx_defer_and_drop_preserve_hook_ownership);
    RUN_TEST(test_w12_burst_pending_tx_done_is_drained_without_rearming);
    RUN_TEST(test_w12_burst_reconfigure_consumes_stale_event_before_ordinary_send);
    RUN_TEST(test_w12_burst_scheduler_rejection_keeps_packet_queued);
#endif
#else
    RUN_TEST(test_w12_adapter_default_gate_refuses_flrc_send_and_releases_packet);
#endif
}

#else
static void deleteW12Adapter() {}
static void runW12AdapterTests() {}
#endif
