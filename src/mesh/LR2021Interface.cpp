#include "configuration.h"

#if (defined(USE_LR2021) || defined(ARCH_PORTDUINO)) && RADIOLIB_EXCLUDE_LR2021 != 1

#include "LR2021Interface.h"
#include "RadioMode.h"
#include "Throttle.h"
#include "UptimeClock.h"
#include "W12FlrcProfile.h"
#include "error.h"
#include "mesh/NodeDB.h"
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
#include "modules/W12BenchmarkModule.h"
#endif
#include <cmath>

namespace
{
bool isFlrcReceptionActive(uint32_t flags, uint32_t &activeReceiveStart)
{
    // FLRC has no LoRa header-valid flag; bound a stale sync/preamble by a maximum frame budget.
    bool detected = flags & (RADIOLIB_LR2021_IRQ_SYNCWORD_VALID | RADIOLIB_LR2021_IRQ_PREAMBLE_DETECTED);
    if (!detected || (flags & W12FlrcProfile::RECEIVE_IRQS)) {
        activeReceiveStart = 0;
        return false;
    }
    if (!activeReceiveStart)
        activeReceiveStart = Time::skipZero(Time::getMillis());
    return Throttle::isWithinTimespanMs(activeReceiveStart, W12FlrcProfile::durationMs(MAX_LORA_PAYLOAD_LEN));
}
} // namespace

LR2021Interface::LR2021Interface(LockingArduinoHal *hal, RADIOLIB_PIN_TYPE cs, RADIOLIB_PIN_TYPE irq, RADIOLIB_PIN_TYPE rst,
                                 RADIOLIB_PIN_TYPE busy)
    : LR20x0Interface(hal, cs, irq, rst, busy)
{
}

bool LR2021Interface::wideLora()
{
    return true;
}

bool LR2021Interface::init()
{
    if (!RadioMode::status(config.lora).configuration_valid) {
        RadioMode::markInitialized(false);
        return false;
    }
    if (!RadioMode::isFlrc()) {
        bool result = LR20x0Interface::init();
        RadioMode::markInitialized(result);
        return result;
    }
    RadioLibInterface::init();
    if (!beginFlrc())
        return false;
    startReceive();
    return !rxOffline;
}

bool LR2021Interface::beginFlrc()
{
    // Full profile setup stops RX; recovery callers must rearm it even if setup fails.
    isReceiving = false;
    activeReceiveStart = 0;
    disableInterrupt();
#if defined(MESHNOLOGY_W12) && !ARCH_PORTDUINO
    pinMode(LR2021_RF_SWITCH_SUBGHZ, OUTPUT);
    digitalWrite(LR2021_RF_SWITCH_SUBGHZ, HIGH);
    pinMode(LR2021_RF_SWITCH_2_4GHZ, OUTPUT);
    digitalWrite(LR2021_RF_SWITCH_2_4GHZ, LOW);
#endif
    lora.irqDioNum = 8;
    int16_t result = W12FlrcProfile::begin(lora);
    RadioMode::markInitialized(result == RADIOLIB_ERR_NONE);
    if (result != RADIOLIB_ERR_NONE) {
        rxOffline = true;
        LOG_ERROR("W12 FLRC profile init failed %s%d", radioLibErr, result);
    } else {
        LOG_INFO("W12 FLRC 915MHz fixed candidate: chip drive -9dBm, RF acceptance pending");
    }
    return result == RADIOLIB_ERR_NONE;
}

bool LR2021Interface::reconfigure()
{
    if (!RadioMode::isFlrc())
        return LR20x0Interface::reconfigure();
    RadioLibInterface::reconfigure();
    // Mode writes are pending until reboot; logical-channel edits retain the active fixed waveform.
    startReceive();
    return !rxOffline;
}

bool LR2021Interface::recoverChipStateLoss()
{
    return RadioMode::isFlrc() ? beginFlrc() : LR20x0Interface::recoverChipStateLoss();
}

int16_t LR2021Interface::standbyFlrc()
{
    int16_t result = lora.standby();
    isReceiving = false;
    activeReceiveStart = 0;
    disableInterrupt();
    // Forced standby cannot claim success for an incomplete transmission.
    completeSending(false);
    RadioLibInterface::setStandby();
    return result;
}

void LR2021Interface::setStandby()
{
    if (!RadioMode::isFlrc()) {
        LR20x0Interface::setStandby();
        return;
    }
    checkNotification(); // Preserve a completed TX before an explicit standby request aborts it.
    if (standbyFlrc() != RADIOLIB_ERR_NONE)
        rxOffline = true;
}

void LR2021Interface::startReceive()
{
    if (!RadioMode::isFlrc()) {
        LR20x0Interface::startReceive();
        return;
    }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
#if defined(MESHTASTIC_W12_BENCHMARK_SINGLE_RX) && MESHTASTIC_W12_BENCHMARK_SINGLE_RX
    constexpr uint32_t rxTimeout = RADIOLIB_LR2021_RX_TIMEOUT_NONE;
#elif defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS)
    constexpr uint32_t rxTimeout = W12FlrcProfile::RX_TIMEOUT_TICKS;
#else
    constexpr uint32_t rxTimeout = RADIOLIB_LR2021_RX_TIMEOUT_INF;
#endif
#else
    constexpr uint32_t rxTimeout = RADIOLIB_LR2021_RX_TIMEOUT_INF;
#endif
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    const uint32_t phaseStartedAt = micros();
    if (w12BenchmarkModule)
        w12BenchmarkModule->onRxArmAttempt();
#endif
    int16_t result = standbyFlrc();
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    W12BenchmarkModule::RxArmStage failureStage = W12BenchmarkModule::RxArmStage::STANDBY;
#endif
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (w12BenchmarkModule)
        w12BenchmarkModule->onRxArmStage(W12BenchmarkModule::RxArmStage::STANDBY, result);
#endif
    auto armReceive = [&]([[maybe_unused]] bool retry) {
#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
        // Finite RX has ended before this full arm. Rejected frames skip readData's FIFO clear.
        // Keep this experiment out of continuous RX, where a second valid frame can be queued.
        result = W12FlrcProfile::clearRxFifo(module);
        failureStage = W12BenchmarkModule::RxArmStage::FIFO_CLEAR;
        if (w12BenchmarkModule)
            w12BenchmarkModule->onRxArmStage(failureStage, result);
        if (result != RADIOLIB_ERR_NONE)
            return;
#endif
        result = lora.startReceive(rxTimeout);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onRxArmStage(W12BenchmarkModule::RxArmStage::RX_START, result, retry);
        failureStage = W12BenchmarkModule::RxArmStage::RX_START;
#endif
    };
    if (result == RADIOLIB_ERR_NONE)
        armReceive(false);
    bool canRecover = result != RADIOLIB_ERR_NONE;
#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
    // Do not silently bypass a failed FIFO clear with a direct RX retry.
    canRecover = canRecover && failureStage != W12BenchmarkModule::RxArmStage::FIFO_CLEAR;
#endif
    if (canRecover && maybeRecoverChipStateLoss())
        armReceive(true);
    // The generic IRQ map misses terminal FLRC LEN_ERROR and command errors.
    if (result == RADIOLIB_ERR_NONE) {
        result = lora.setIrqFlags(W12FlrcProfile::RECEIVE_IRQS);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onRxArmStage(W12BenchmarkModule::RxArmStage::IRQ_MAP, result);
        failureStage = W12BenchmarkModule::RxArmStage::IRQ_MAP;
#endif
    }
    if (result != RADIOLIB_ERR_NONE) {
        rxOffline = true;
        RadioMode::markInitialized(false);
        LOG_ERROR("FLRC RX offline %s%d", radioLibErr, result);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule) {
            w12BenchmarkModule->onRxArmFinished(result, failureStage);
            w12BenchmarkModule->onRadioPhase(W12BenchmarkModule::RadioPhase::RX_START,
                                             static_cast<uint32_t>(micros() - phaseStartedAt));
        }
#endif
        return;
    }
    RadioLibInterface::startReceive();
    RadioMode::markInitialized(true);
    enableInterrupt(isrRxLevel0);
    checkRxDoneIrqFlag();
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (w12BenchmarkModule) {
        w12BenchmarkModule->onRxArmFinished(RADIOLIB_ERR_NONE, W12BenchmarkModule::RxArmStage::NONE);
        w12BenchmarkModule->onRadioPhase(W12BenchmarkModule::RadioPhase::RX_START,
                                         static_cast<uint32_t>(micros() - phaseStartedAt));
    }
#endif
}

bool LR2021Interface::isChannelActive()
{
    if (!RadioMode::isFlrc())
        return LR20x0Interface::isChannelActive();
    // Observe energy while continuous RX remains armed. Failed observations defer transmission.
    if (rxOffline || !isReceiving) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::NOT_READY);
#endif
        return true;
    }
    for (unsigned i = 0; i < 3; ++i) {
        float rssi = 0;
        if (W12FlrcProfile::readRssi(module, false, rssi) != RADIOLIB_ERR_NONE) {
            uint32_t flags = 0;
            if (W12FlrcProfile::readIrqFlags(module, flags) == RADIOLIB_ERR_NONE) {
                if (flags & W12FlrcProfile::RECEIVE_IRQS) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
                    if (w12BenchmarkModule)
                        w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::RX_IRQ_PENDING);
#endif
                    // A failed energy sample must not reset the chip before a completed RX is consumed.
                    notify(ISR_RX, true);
                    return true;
                }
                if (isFlrcReceptionActive(flags, activeReceiveStart)) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
                    if (w12BenchmarkModule)
                        w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::RX_ACTIVE);
#endif
                    return true;
                }
            }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
            if (w12BenchmarkModule)
                w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::RSSI_READ_ERROR);
#endif
            maybeRecoverChipStateLoss();
            return true;
        }
        if (!std::isfinite(rssi)) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
            if (w12BenchmarkModule)
                w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::RSSI_INVALID);
#endif
            return true;
        }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onCcaRssiSample(static_cast<int16_t>(lround(rssi)));
#endif
        if (rssi >= W12FlrcProfile::BUSY_THRESHOLD_DBM) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
            if (w12BenchmarkModule)
                w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::ENERGY_BUSY);
#endif
            return true;
        }
        if (isActivelyReceiving()) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
            if (w12BenchmarkModule)
                w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::RX_ACTIVE);
#endif
            return true;
        }
        if (receiveIrqPending()) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
            if (w12BenchmarkModule)
                w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::RX_IRQ_PENDING);
#endif
            return true;
        }
        if (i != 2)
            delayMicroseconds(W12FlrcProfile::OBSERVATION_US);
    }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (w12BenchmarkModule)
        w12BenchmarkModule->onCcaDecision(W12BenchmarkModule::CcaReason::FREE);
#endif
    setStandby();
    return rxOffline;
}

bool LR2021Interface::isActivelyReceiving()
{
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    return readW12ActiveReceiveState() != W12ActiveReceiveState::INACTIVE;
#else
    if (!RadioMode::isFlrc())
        return LR20x0Interface::isActivelyReceiving();
    uint32_t flags = 0;
    if (W12FlrcProfile::readIrqFlags(module, flags) != RADIOLIB_ERR_NONE)
        return true;
    return isFlrcReceptionActive(flags, activeReceiveStart);
#endif
}

int16_t LR2021Interface::getCurrentRSSI()
{
    if (!RadioMode::isFlrc())
        return LR20x0Interface::getCurrentRSSI();
    float rssi = 0;
    return W12FlrcProfile::readRssi(module, false, rssi) == RADIOLIB_ERR_NONE ? lround(rssi) : NOISE_FLOOR_INVALID;
}

void LR2021Interface::addReceiveMetadata(meshtastic_MeshPacket *mp)
{
    if (!RadioMode::isFlrc()) {
        LR20x0Interface::addReceiveMetadata(mp);
        return;
    }
    mp->rx_snr = 0;
    mp->rx_snr_unavailable = true;
    float rssi = 0;
    mp->has_rx_rssi = W12FlrcProfile::readRssi(module, true, rssi) == RADIOLIB_ERR_NONE;
    if (mp->has_rx_rssi)
        mp->rx_rssi = lround(rssi);
}

uint32_t LR2021Interface::getPacketTime(uint32_t length, bool received)
{
    return RadioMode::isFlrc() ? W12FlrcProfile::durationMs(length) : LR20x0Interface::getPacketTime(length, received);
}

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
W12ActiveReceiveState LR2021Interface::readW12ActiveReceiveState()
{
    if (!RadioMode::isFlrc())
        return LR20x0Interface::isActivelyReceiving() ? W12ActiveReceiveState::ACTIVE : W12ActiveReceiveState::INACTIVE;

    uint32_t flags = 0;
    if (W12FlrcProfile::readIrqFlags(module, flags) != RADIOLIB_ERR_NONE)
        return W12ActiveReceiveState::IRQ_READ_FAILURE;
    return isFlrcReceptionActive(flags, activeReceiveStart) ? W12ActiveReceiveState::ACTIVE : W12ActiveReceiveState::INACTIVE;
}

bool LR2021Interface::readW12RxLiveness(W12RxLivenessSample &sample)
{
    sample = W12RxLivenessSample{};
    if (!RadioMode::isFlrc())
        return false;

    sample.softwareState = getW12DiagnosticRadioState();
    sample.chipStatsResult = lora.getFlrcRxStats(&sample.chipRxPackets, &sample.chipCrcErrors, &sample.chipLenErrors);
    sample.irqReadResult = W12FlrcProfile::readIrqFlags(module, sample.rawIrqFlags, &sample.rawStatus);

    float rssi = 0;
    sample.rssiReadResult = W12FlrcProfile::readRssi(module, false, rssi);
    if (sample.rssiReadResult == RADIOLIB_ERR_NONE)
        sample.rssiDbm = static_cast<int16_t>(lround(rssi));
    return true;
}

bool LR2021Interface::readW12RxRecovery(W12RxRecoverySample &sample)
{
    sample = W12RxRecoverySample{};
    if (!RadioMode::isFlrc() || !module.hal)
        return false;

    sample.sampledAtMs = Time::getMillis();
    sample.activeReceiveStartMs = activeReceiveStart;
    sample.softwareState = getW12DiagnosticRadioState();
    sample.busyLevel = static_cast<uint8_t>(module.hal->digitalRead(module.getGpio()) != 0);
    sample.dioLevel = static_cast<uint8_t>(module.hal->digitalRead(module.getIrq()) != 0);
    sample.irqReadResult = W12FlrcProfile::readIrqFlags(module, sample.rawIrqFlags, &sample.rawStatus);
    sample.fifoFlagsResult = W12FlrcProfile::readFifoIrqFlags(module, sample.fifoRxFlags, sample.fifoTxFlags);
    sample.fifoLevelResult = W12FlrcProfile::readRxFifoLevel(module, sample.rxFifoLevel);
    sample.errorsResult = lora.getErrors(&sample.chipErrors);
    return true;
}

bool LR2021Interface::performW12RxRearm(W12RxRearmResult &result)
{
    result = W12RxRearmResult{};
    if (!RadioMode::isFlrc() || isSending() || packetsInTxQueue() != 0)
        return false;
    result.beforeState = getW12DiagnosticRadioState();
    const uint32_t startedAt = micros();
    LR2021Interface::startReceive();
    result.durationUs = static_cast<uint32_t>(micros() - startedAt);
    result.afterState = getW12DiagnosticRadioState();
    result.softwareArmed = (result.afterState & 0x01u) != 0 && (result.afterState & 0x02u) == 0;
    return true;
}
#endif

bool LR2021Interface::receiveIrqPending()
{
    if (!RadioMode::isFlrc())
        return RadioLibInterface::receiveIrqPending();
    uint32_t flags = 0;
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    const bool diagnosticPoll = w12BenchmarkModule && isW12DiagnosticPollContext();
    uint16_t rawStatus = 0;
#endif
    const int16_t result =
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        diagnosticPoll ? W12FlrcProfile::readIrqFlags(module, flags, &rawStatus) : W12FlrcProfile::readIrqFlags(module, flags);
#else
        W12FlrcProfile::readIrqFlags(module, flags);
#endif
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (diagnosticPoll)
        w12BenchmarkModule->onRadioPollRx(result, flags, result != RADIOLIB_ERR_NONE || (flags & W12FlrcProfile::RECEIVE_IRQS),
                                          rawStatus);
#endif
    return result != RADIOLIB_ERR_NONE || (flags & W12FlrcProfile::RECEIVE_IRQS);
}

bool LR2021Interface::validReceiveIrq()
{
    if (!RadioMode::isFlrc())
        return true;
    uint32_t flags = 0;
    int16_t result = W12FlrcProfile::readIrqFlags(module, flags);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (w12BenchmarkModule)
        w12BenchmarkModule->onRxIrq(result == RADIOLIB_ERR_NONE, flags & RADIOLIB_LR2021_IRQ_RX_DONE,
                                    flags & RADIOLIB_LR2021_IRQ_CRC_ERROR, flags & RADIOLIB_LR2021_IRQ_LEN_ERROR,
                                    flags & RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR, flags & RADIOLIB_LR2021_IRQ_TIMEOUT,
                                    flags & (RADIOLIB_LR2021_IRQ_ERROR | RADIOLIB_LR2021_IRQ_CMD_ERROR));
#endif
    if (result == RADIOLIB_ERR_NONE && W12FlrcProfile::acceptsIrq(flags))
        return true;
    LOG_WARN("Reject FLRC RX status=%d IRQ=0x%x", result, flags);
    lora.clearIrqFlags(RADIOLIB_LR2021_IRQ_ALL);
    return false;
}

bool LR2021Interface::validTransmitIrq()
{
    if (!RadioMode::isFlrc())
        return true;
    uint32_t flags = 0;
    return W12FlrcProfile::readIrqFlags(module, flags) == RADIOLIB_ERR_NONE && (flags & RADIOLIB_LR2021_IRQ_TX_DONE) &&
           !(flags & W12FlrcProfile::ERROR_IRQS);
}

bool LR2021Interface::armTransmitBeforeStart()
{
    return RadioMode::isFlrc();
}

void LR2021Interface::onTransmitStarted()
{
    if (RadioMode::isFlrc())
        scheduleIrqPollTick();
}

void LR2021Interface::handleSoftwareLoraIrqPoll()
{
    if (!RadioMode::isFlrc() || !sendingPacket)
        return;
    uint32_t flags = 0;
    const int16_t result = W12FlrcProfile::readIrqFlags(module, flags);
    if (result != RADIOLIB_ERR_NONE || (flags & (RADIOLIB_LR2021_IRQ_TX_DONE | W12FlrcProfile::ERROR_IRQS)) ||
        Throttle::hasElapsed(lastTxStart, W12FlrcProfile::TX_TIMEOUT_MS)) {
        // Timeout uses the normal completion path, which verifies TX_DONE before counting success.
        deliverPendingIrqFromPoll(ISR_TX);
    } else {
        scheduleIrqPollTick();
    }
}

bool LR2021Interface::sleep()
{
    if (!RadioMode::isFlrc())
        return LR20x0Interface::sleep();
    (void)standbyFlrc();
    int16_t result = lora.sleep(false, 0);
    RadioMode::markInitialized(false);
#if defined(MESHNOLOGY_W12) && !ARCH_PORTDUINO
    digitalWrite(LR2021_RF_SWITCH_SUBGHZ, LOW);
    digitalWrite(LR2021_RF_SWITCH_2_4GHZ, LOW);
#endif
    return result == RADIOLIB_ERR_NONE;
}
#endif
