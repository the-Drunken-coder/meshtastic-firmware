#include "configuration.h"

#if (defined(USE_LR2021) || defined(ARCH_PORTDUINO)) && RADIOLIB_EXCLUDE_LR2021 != 1

#include "LR2021Interface.h"
#include "RadioMode.h"
#include "Throttle.h"
#include "UptimeClock.h"
#include "W12FlrcProfile.h"
#include "error.h"
#include "mesh/NodeDB.h"
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
    if (standbyFlrc() != RADIOLIB_ERR_NONE)
        rxOffline = true;
}

void LR2021Interface::startReceive()
{
    if (!RadioMode::isFlrc()) {
        LR20x0Interface::startReceive();
        return;
    }
    int16_t result = standbyFlrc();
    if (result == RADIOLIB_ERR_NONE)
        result = lora.startReceive(RADIOLIB_LR2021_RX_TIMEOUT_INF);
    if (result != RADIOLIB_ERR_NONE && maybeRecoverChipStateLoss())
        result = lora.startReceive(RADIOLIB_LR2021_RX_TIMEOUT_INF);
    // The generic IRQ map misses terminal FLRC LEN_ERROR and command errors.
    if (result == RADIOLIB_ERR_NONE)
        result = lora.setIrqFlags(W12FlrcProfile::RECEIVE_IRQS);
    if (result != RADIOLIB_ERR_NONE) {
        rxOffline = true;
        RadioMode::markInitialized(false);
        LOG_ERROR("FLRC RX offline %s%d", radioLibErr, result);
        return;
    }
    RadioLibInterface::startReceive();
    RadioMode::markInitialized(true);
    enableInterrupt(isrRxLevel0);
    checkRxDoneIrqFlag();
}

bool LR2021Interface::isChannelActive()
{
    if (!RadioMode::isFlrc())
        return LR20x0Interface::isChannelActive();
    // Observe energy while continuous RX remains armed. Failed observations defer transmission.
    if (rxOffline || !isReceiving)
        return true;
    for (unsigned i = 0; i < 3; ++i) {
        float rssi = 0;
        if (W12FlrcProfile::readRssi(module, false, rssi) != RADIOLIB_ERR_NONE) {
            uint32_t flags = 0;
            if (W12FlrcProfile::readIrqFlags(module, flags) == RADIOLIB_ERR_NONE) {
                if (flags & W12FlrcProfile::RECEIVE_IRQS) {
                    // A failed energy sample must not reset the chip before a completed RX is consumed.
                    notify(ISR_RX, true);
                    return true;
                }
                if (isFlrcReceptionActive(flags, activeReceiveStart))
                    return true;
            }
            maybeRecoverChipStateLoss();
            return true;
        }
        if (!std::isfinite(rssi) || rssi >= W12FlrcProfile::BUSY_THRESHOLD_DBM || isActivelyReceiving() || receiveIrqPending())
            return true;
        if (i != 2)
            delayMicroseconds(W12FlrcProfile::OBSERVATION_US);
    }
    setStandby();
    return rxOffline;
}

bool LR2021Interface::isActivelyReceiving()
{
    if (!RadioMode::isFlrc())
        return LR20x0Interface::isActivelyReceiving();
    uint32_t flags = 0;
    if (W12FlrcProfile::readIrqFlags(module, flags) != RADIOLIB_ERR_NONE)
        return true;
    return isFlrcReceptionActive(flags, activeReceiveStart);
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

bool LR2021Interface::receiveIrqPending()
{
    if (!RadioMode::isFlrc())
        return RadioLibInterface::receiveIrqPending();
    uint32_t flags = 0;
    return W12FlrcProfile::readIrqFlags(module, flags) != RADIOLIB_ERR_NONE || (flags & W12FlrcProfile::RECEIVE_IRQS);
}

bool LR2021Interface::validReceiveIrq()
{
    if (!RadioMode::isFlrc())
        return true;
    uint32_t flags = 0;
    int16_t result = W12FlrcProfile::readIrqFlags(module, flags);
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
