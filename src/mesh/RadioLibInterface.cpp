#include "RadioLibInterface.h"
#include "MeshTypes.h"
#include "NodeDB.h"
#include "PowerMon.h"
#include "RadioMode.h"
#include "RadioTxHook.h"
#include "SPILock.h"
#include "Throttle.h"
#include "UptimeClock.h"
#include "configuration.h"
#include "error.h"
#include "main.h"
#include "mesh-pb-constants.h"
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
#include "modules/W12BenchmarkModule.h"
#endif
#include <pb_decode.h>
#include <pb_encode.h>

#if ARCH_PORTDUINO
#include "PortduinoGlue.h"
#include "meshUtils.h"
#endif

void LockingArduinoHal::spiBeginTransaction()
{
    spiLock->lock();

    ArduinoHal::spiBeginTransaction();
}

void LockingArduinoHal::spiEndTransaction()
{
    ArduinoHal::spiEndTransaction();

    spiLock->unlock();
}

#if ARCH_PORTDUINO
void LockingArduinoHal::spiTransfer(uint8_t *out, size_t len, uint8_t *in)
{
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    const bool collect = benchmarkMetrics && benchmarkMetrics->isCollecting();
    const uint32_t startedAtUs = collect ? static_cast<uint32_t>(micros()) : 0;
#endif
    spi->transfer(out, in, len);
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    if (collect) {
        const uint32_t durationUs = static_cast<uint32_t>(static_cast<uint32_t>(micros()) - startedAtUs);
        benchmarkMetrics->recordTransfer(durationUs, len);
    }
#endif
}
#endif

#if defined(ARCH_ESP32) && defined(MESHNOLOGY_W12) && defined(MESHTASTIC_W12_BENCHMARK) && MESHTASTIC_W12_BENCHMARK &&           \
    defined(MESHTASTIC_W12_BENCHMARK_BULK_SPI) && MESHTASTIC_W12_BENCHMARK_BULK_SPI
void LockingArduinoHal::spiTransfer(uint8_t *out, size_t len, uint8_t *in)
{
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    const bool collect = benchmarkMetrics && benchmarkMetrics->isCollecting();
    const uint32_t startedAtUs = collect ? static_cast<uint32_t>(micros()) : 0;
#endif
    w12_bulk_spi::transfer(*spi, out, len, in);
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    if (collect) {
        const uint32_t durationUs = static_cast<uint32_t>(static_cast<uint32_t>(micros()) - startedAtUs);
        benchmarkMetrics->recordTransfer(durationUs, len);
    }
#endif
}
#endif

#if W12_BENCHMARK_HAL_TIMING_ENABLED && !ARCH_PORTDUINO &&                                                                       \
    !(defined(ARCH_ESP32) && defined(MESHNOLOGY_W12) && defined(MESHTASTIC_W12_BENCHMARK) && MESHTASTIC_W12_BENCHMARK &&         \
      defined(MESHTASTIC_W12_BENCHMARK_BULK_SPI) && MESHTASTIC_W12_BENCHMARK_BULK_SPI)
void LockingArduinoHal::spiTransfer(uint8_t *out, size_t len, uint8_t *in)
{
    const bool collect = benchmarkMetrics && benchmarkMetrics->isCollecting();
    const uint32_t startedAtUs = collect ? static_cast<uint32_t>(micros()) : 0;
    ArduinoHal::spiTransfer(out, len, in);
    if (collect) {
        const uint32_t durationUs = static_cast<uint32_t>(static_cast<uint32_t>(micros()) - startedAtUs);
        benchmarkMetrics->recordTransfer(durationUs, len);
    }
}
#endif

#if W12_BENCHMARK_HAL_TIMING_ENABLED
void LockingArduinoHal::yield()
{
    const bool collect = benchmarkMetrics && benchmarkMetrics->isCollecting();
    const uint32_t startedAtUs = collect ? static_cast<uint32_t>(micros()) : 0;
    ArduinoHal::yield();
    if (collect) {
        const uint32_t durationUs = static_cast<uint32_t>(static_cast<uint32_t>(micros()) - startedAtUs);
        benchmarkMetrics->recordYield(durationUs);
    }
}
#endif

RadioLibInterface::RadioLibInterface(LockingArduinoHal *hal, RADIOLIB_PIN_TYPE cs, RADIOLIB_PIN_TYPE irq, RADIOLIB_PIN_TYPE rst,
                                     RADIOLIB_PIN_TYPE busy, PhysicalLayer *_iface)
    : NotifiedWorkerThread("RadioIf"), module(hal, cs, irq, rst, busy)
#if W12_BENCHMARK_HAL_TIMING_ENABLED
      ,
      hal(hal), halMetrics()
#endif
      ,
      iface(_iface)
{
    instance = this;

#if W12_BENCHMARK_HAL_TIMING_ENABLED
    if (this->hal)
        this->hal->attachW12BenchmarkMetrics(&halMetrics);
#endif

    // Initialize unused sample slots to a sane default; sample count controls averaging.
    for (uint8_t i = 0; i < NOISE_FLOOR_SAMPLES; i++) {
        noiseFloorSamples[i] = NOISE_FLOOR_DEFAULT;
    }

#if defined(ARCH_STM32WL) && defined(USE_SX1262)
    module.setCb_digitalWrite(stm32wl_emulate_digitalWrite);
    module.setCb_digitalRead(stm32wl_emulate_digitalRead);
#endif
}

#ifdef ARCH_ESP32
// ESP32 doesn't use that flag
#define YIELD_FROM_ISR(x) portYIELD_FROM_ISR()
#else
#define YIELD_FROM_ISR(x) portYIELD_FROM_ISR(x)
#endif

void INTERRUPT_ATTR RadioLibInterface::isrLevel0Common(PendingISR cause)
{
    instance->disableInterrupt();

    BaseType_t xHigherPriorityTaskWoken;
    instance->notifyFromISR(&xHigherPriorityTaskWoken, cause, true);

    /* Force a context switch if xHigherPriorityTaskWoken is now set to pdTRUE.
    The macro used to do this is dependent on the port and may be called
    portEND_SWITCHING_ISR. */
    YIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

void INTERRUPT_ATTR RadioLibInterface::isrRxLevel0()
{
    isrLevel0Common(ISR_RX);
}

void INTERRUPT_ATTR RadioLibInterface::isrTxLevel0()
{
    isrLevel0Common(ISR_TX);
}

/** Our ISR code currently needs this to find our active instance
 */
RadioLibInterface *RadioLibInterface::instance;

/** Could we send right now (i.e. either not actively receiving or transmitting)? */
bool RadioLibInterface::canSendImmediately()
{
    // We wait _if_ we are partially though receiving a packet (rather than just merely waiting for one).
    // To do otherwise would be doubly bad because not only would we drop the packet that was on the way in,
    // we almost certainly guarantee no one outside will like the packet we are sending.
    bool busyTx = sendingPacket != NULL;
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    const W12ActiveReceiveState activeReceiveState = isReceiving ? readW12ActiveReceiveState() : W12ActiveReceiveState::INACTIVE;
    bool busyRx = activeReceiveState != W12ActiveReceiveState::INACTIVE;
#else
    bool busyRx = isReceiving && isActivelyReceiving();
#endif

    if (busyTx || busyRx) {
        if (busyTx) {
            LOG_WARN("Can not send yet, busyTx");
        }
        // If we've been trying to send the same packet more than one minute and we haven't gotten a
        // TX IRQ from the radio, the radio is probably broken.
        if (busyTx && !Throttle::isWithinTimespanMs(lastTxStart, 60000)) {
            LOG_ERROR("Hardware Failure! busyTx >60s");
            RECORD_CRITICALERROR(meshtastic_CriticalErrorCode_TRANSMIT_FAILED);
            // reboot in 5 seconds when this condition occurs.
            rebootAtMsec = Time::skipZero(lastTxStart + 65000);
        }
        if (busyRx) {
            LOG_WARN("Can not send yet, busyRx");
        }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule) {
            if (busyTx)
                w12BenchmarkModule->onPreCanSendDeferred(txQueue.getFront(), W12BenchmarkModule::PreSendBusyReason::BUSY_TX);
            else if (activeReceiveState == W12ActiveReceiveState::IRQ_READ_FAILURE)
                w12BenchmarkModule->onPreCanSendDeferred(txQueue.getFront(),
                                                         W12BenchmarkModule::PreSendBusyReason::BUSY_RX_IRQ_READ_FAILURE);
            else
                w12BenchmarkModule->onPreCanSendDeferred(txQueue.getFront(),
                                                         W12BenchmarkModule::PreSendBusyReason::BUSY_RX_ACTIVE);
        }
#endif
        return false;
    } else
        return true;
}

bool RadioLibInterface::receiveDetected(uint32_t irq, unsigned long syncWordHeaderValidFlag, unsigned long preambleDetectedFlag)
{
    bool detected = (irq & (syncWordHeaderValidFlag | preambleDetectedFlag));
    // Handle false detections
    if (detected) {
        if (!activeReceiveStart) {
            activeReceiveStart = Time::skipZero(Time::getMillis());
        } else if (!Throttle::isWithinTimespanMs(activeReceiveStart, 2 * preambleTimeMsec)) {
            if (!(irq & syncWordHeaderValidFlag)) {
                // The HEADER_VALID flag should be set by now if it was really a packet, so ignore PREAMBLE_DETECTED flag
                activeReceiveStart = 0;
                LOG_TRACE("Ignore false preamble detection");
                return false;
            } else {
                uint32_t maxPacketTimeMsec = getPacketTime(meshtastic_Constants_DATA_PAYLOAD_LEN + sizeof(PacketHeader));
                if (!Throttle::isWithinTimespanMs(activeReceiveStart, maxPacketTimeMsec)) {
                    // We should have gotten an RX_DONE IRQ by now if it was really a packet, so ignore HEADER_VALID flag
                    activeReceiveStart = 0;
                    LOG_TRACE("Ignore false header detection");
                    return false;
                }
            }
        }
    }
    return detected;
}

/// Send a packet (possibly by enquing in a private fifo).  This routine will
/// later free() the packet to pool.  This routine is not allowed to stall because it is called from
/// bluetooth comms code.  If the txmit queue is empty it might return an error
ErrorCode RadioLibInterface::send(meshtastic_MeshPacket *p)
{
    if (disabled || !RadioMode::canTransmit()) {
        LOG_WARN("Radio TX disabled: invalid, inactive, or RF-gated profile");
        notifyTxFinished(p, TxState::Rejected);
        RadioTxHooks::packetReleased(this, p);
        packetPool.release(p);
        return ERRNO_DISABLED;
    }
#ifndef DISABLE_WELCOME_UNSET
    if ((RadioMode::isFlrc() ? RadioMode::activeConfig().region : config.lora.region) ==
        meshtastic_Config_LoRaConfig_RegionCode_UNSET) {
        LOG_WARN("send - lora tx disabled: Region unset");
        notifyTxFinished(p, TxState::Rejected);
        RadioTxHooks::packetReleased(this, p);
        packetPool.release(p);
        return ERRNO_DISABLED;
    }

#endif

    if (p->to == NODENUM_BROADCAST_NO_LORA) {
        LOG_DEBUG("Drop no-LoRa pkt");
        notifyTxFinished(p, TxState::Rejected);
        RadioTxHooks::packetReleased(this, p);
        return ERRNO_SHOULD_RELEASE;
    }

    // Sometimes when testing it is useful to be able to never turn on the xmitter
#ifndef LORA_DISABLE_SENDING
    printPacket("enqueue for send", p);

    LOG_TRACE("txGood=%d,txRelay=%d,rxGood=%d,rxBad=%d", txGood, txRelay, rxGood, rxBad);
    bool dropped = false;
    meshtastic_MeshPacket *evicted = nullptr;
    ErrorCode res = txQueue.enqueue(p, &dropped, &evicted) ? ERRNO_OK : ERRNO_UNKNOWN;
    if (evicted) {
        notifyTxFinished(evicted, TxState::Dropped);
        RadioTxHooks::packetReleased(this, evicted);
        packetPool.release(evicted);
    }

    if (dropped) {
        txDrop++;
    }

    if (res != ERRNO_OK) { // we weren't able to queue it, so we must drop it to prevent leaks
        notifyTxFinished(p, TxState::Rejected);
        RadioTxHooks::packetReleased(this, p);
        packetPool.release(p);
        return res;
    }

    // set (random) transmit delay to let others reconfigure their radio,
    // to avoid collisions and implement timing-based flooding
    setTransmitDelay();

    return res;
#else
    notifyTxFinished(p, TxState::Rejected);
    RadioTxHooks::packetReleased(this, p);
    packetPool.release(p);
    return ERRNO_DISABLED;
#endif
}

meshtastic_QueueStatus RadioLibInterface::getQueueStatus()
{
    meshtastic_QueueStatus qs;

    qs.res = qs.mesh_packet_id = 0;
    qs.free = txQueue.getFree();
    qs.maxlen = txQueue.getMaxLen();

    return qs;
}

bool RadioLibInterface::canSleep(bool deepSleep)
{
    // A packet being actively transmitted has already left the TX queue (sendingPacket), so
    // check it separately. It only vetoes deep sleep: light sleep keeps the radio powered and
    // the TX finishes on its own, but deep sleep powers the radio down and would truncate the
    // packet on air.
    bool res = txQueue.empty() && !(deepSleep && isSending());
    if (!res) { // only print debug messages if we are vetoing sleep
        LOG_DEBUG("Radio wait to sleep, txEmpty=%d, txInFlight=%d", txQueue.empty(), isSending());
    }
    return res;
}

/** Allow other firmware components to ask whether we are currently sending a packet
Initially implemented to protect T-Echo's capacitive touch button from spurious presses during tx
*/
bool RadioLibInterface::isSending()
{
    return sendingPacket != NULL;
}

/** Attempt to cancel a previously sent packet.  Returns true if a packet was found we could cancel */
bool RadioLibInterface::cancelSending(NodeNum from, PacketId id)
{
    bool removed = false;
    while (auto *p = txQueue.remove(from, id)) {
        notifyTxFinished(p, TxState::Cancelled);
        RadioTxHooks::packetReleased(this, p);
        packetPool.release(p);
        removed = true;
    }
    return removed;
}

/** Attempt to find a packet in the TxQueue. Returns true if the packet was found. */
bool RadioLibInterface::findInTxQueue(NodeNum from, PacketId id)
{
    return txQueue.find(from, id);
}

void RadioLibInterface::updateNoiseFloor()
{
    // Only sample from idle receive mode. TX/RX-critical paths must return to radio work quickly.
    if (!isReceiving || sendingPacket != NULL || isActivelyReceiving() || isIRQPending()) {
        return;
    }

    if (Throttle::isWithinTimespanMs(lastNoiseFloorUpdate, NOISE_FLOOR_UPDATE_INTERVAL_MS)) {
        return;
    }
    lastNoiseFloorUpdate = Time::getMillis();

    int16_t rssi = getCurrentRSSI();
    if (rssi == NOISE_FLOOR_INVALID || rssi >= 0 || rssi < NOISE_FLOOR_VALID_MIN) {
        LOG_DEBUG("Skipping invalid RSSI reading: %d", rssi);
        return;
    }

    noiseFloorSamples[currentSampleIndex] = (int32_t)rssi;
    currentSampleIndex++;

    if (currentSampleIndex >= NOISE_FLOOR_SAMPLES) {
        currentSampleIndex = 0;
        isNoiseFloorBufferFull = true;
    }

    currentNoiseFloor = getAverageNoiseFloorInternal();

    LOG_TRACE("Noise floor: %d dBm (samples: %d, latest: %d dBm)", currentNoiseFloor, getNoiseFloorSampleCountInternal(), rssi);
}

uint8_t RadioLibInterface::getNoiseFloorSampleCountInternal() const
{
    return isNoiseFloorBufferFull ? NOISE_FLOOR_SAMPLES : currentSampleIndex;
}

int32_t RadioLibInterface::getAverageNoiseFloorInternal() const
{
    uint8_t sampleCount = getNoiseFloorSampleCountInternal();

    if (sampleCount == 0) {
        return NOISE_FLOOR_DEFAULT;
    }

    int32_t sum = 0;
    for (uint8_t i = 0; i < sampleCount; i++) {
        sum += noiseFloorSamples[i];
    }

    return sum / sampleCount;
}

int32_t RadioLibInterface::getAverageNoiseFloor()
{
    return getAverageNoiseFloorInternal();
}

int32_t RadioLibInterface::getNoiseFloor()
{
    return currentNoiseFloor;
}

bool RadioLibInterface::hasNoiseFloorSamples()
{
    return getNoiseFloorSampleCountInternal() > 0;
}

uint8_t RadioLibInterface::getNoiseFloorSampleCount()
{
    return getNoiseFloorSampleCountInternal();
}

void RadioLibInterface::resetNoiseFloor()
{
    currentSampleIndex = 0;
    isNoiseFloorBufferFull = false;
    currentNoiseFloor = NOISE_FLOOR_DEFAULT;
    LOG_INFO("Noise floor reset - rolling window will restart");
}

bool RadioLibInterface::randomBytes(uint8_t *buffer, size_t length)
{
    if (!buffer || length == 0 || !iface) {
        return false;
    }

    // Older RadioLib versions only expose random(min, max), so fill the buffer byte-by-byte.
    for (size_t i = 0; i < length; ++i) {
        int32_t value = iface->random(0, 255);
        if (value < 0) {
            return false;
        }
        buffer[i] = static_cast<uint8_t>(value & 0xFF);
    }

    return true;
}

/** radio helper thread callback.
We never immediately transmit after any operation (either Rx or Tx). Instead we should wait a random multiple of
'slotTimes' (see definition in RadioInterface.h) taken from a contention window (CW) to lower the chance of collision.
The CW size is determined by setTransmitDelay() and depends either on the current channel utilization or SNR in case
of a flooding message. After this, we perform channel activity detection (CAD) and reset the transmit delay if it is
currently active.
*/
// In software-IRQ-poll mode (LORA_DIO1_SOFTWARE_POLL) a 1ms poll tick is almost always pending, so
// TX timers must be allowed to overwrite the pending notification or TX scheduling starves. On all
// other targets keep the historical non-overwriting behavior.
#ifdef LORA_DIO1_SOFTWARE_POLL
static constexpr bool txTimerOverwrite = true;
#else
static constexpr bool txTimerOverwrite = false;
#endif

// cppcheck-suppress constParameterPointer ; a function pointer can't meaningfully point to const
bool RadioLibInterface::isIsrTxCallback(void (*callback)())
{
    return callback == isrTxLevel0;
}

#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
bool RadioLibInterface::isW12BurstPacket(const meshtastic_MeshPacket *packet) const
{
    if (!packet || !w12BenchmarkModule || !RadioMode::isFlrc() || !RadioMode::canTransmit() || disabled)
        return false;

    const W12BenchmarkModule::Stats stats = w12BenchmarkModule->getStats();
    if (!stats.prepared || !stats.running || stats.elapsedMs >= stats.config.durationMs ||
        nodeDB->getNodeNum() != stats.config.source || !w12BenchmarkModule->ownsTx(packet))
        return false;

    // This gate deliberately uses only the encrypted envelope and owner identity. It never decodes ciphertext.
    return packet->which_payload_variant == meshtastic_MeshPacket_encrypted_tag && packet->pki_encrypted && !packet->want_ack &&
           packet->hop_limit == 0 && packet->hop_start == 0 && packet->from == stats.config.source &&
           packet->to == stats.config.destination &&
           packet->transport_mechanism == meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL && packet->channel == 0 &&
           !packet->via_mqtt && packet->priority == meshtastic_MeshPacket_Priority_BACKGROUND && packet->tx_after == 0;
}

void RadioLibInterface::clearW12BurstState()
{
    w12Burst = W12BurstState{};
}

void RadioLibInterface::cancelW12Burst()
{
    w12BurstResumeAfterStale = false;
    if (w12Burst.active || w12Burst.timerPending) {
        if (w12BenchmarkModule)
            w12BenchmarkModule->onW12BurstAborted();
        clearW12BurstState();
    }
}

void RadioLibInterface::beginW12StandbyDrain()
{
    if (w12BurstSuppressionDepth != UINT8_MAX)
        ++w12BurstSuppressionDepth;
    w12BurstArmSuppressed = true;
    cancelW12Burst();
}

void RadioLibInterface::endW12StandbyDrain()
{
    if (w12BurstSuppressionDepth == 0)
        return;
    if (--w12BurstSuppressionDepth == 0)
        w12BurstArmSuppressed = false;
}

void RadioLibInterface::markW12BurstNormalResumeAfterStale()
{
    w12BurstResumeAfterStale = true;
}

void RadioLibInterface::finishW12BurstToNormal()
{
    cancelW12Burst();
    if (!disabled)
        startReceive();
    setTransmitDelay();
}

void RadioLibInterface::abortW12BurstToNormal()
{
    const bool staleGuardEventMayRemain = w12Burst.timerPending;
    if (w12Burst.active || w12Burst.timerPending) {
        if (sendingPacket) {
            // Ending the producer window cancels future burst scheduling, not the physical
            // frame already in flight. Its normal completion validates TX_DONE, rearms RX,
            // and drains admitted packets through ordinary scheduling.
            cancelW12Burst();
            return;
        }
        finishW12BurstToNormal();
        // finishW12BurstToNormal() schedules the ordinary timer after the
        // dedicated one-slot event has been cancelled from state. The event
        // itself cannot be cancelled, so let its later stale dispatch restore
        // that ordinary timer. Explicit standby never enters this helper and
        // therefore cannot wake the radio through a stale event.
        if (staleGuardEventMayRemain)
            w12BurstResumeAfterStale = true;
    }
}

bool RadioLibInterface::armW12BurstAfterSuccess(bool currentPacketEligible)
{
    const bool priorActive = w12Burst.active;
    if (!currentPacketEligible) {
        if (priorActive)
            cancelW12Burst();
        return false;
    }

    const uint8_t completedFrames = priorActive ? static_cast<uint8_t>(w12Burst.completedFrames + 1) : 1;
    if (priorActive && w12BenchmarkModule)
        w12BenchmarkModule->onW12BurstFrame();

    if (completedFrames >= W12_BURST_MAX_FRAMES) {
        clearW12BurstState();
        return false;
    }

    meshtastic_MeshPacket *next = txQueue.getFront();
    const bool nextEligible = isW12BurstPacket(next);
    const bool nextHoldsRadio = next && RadioTxHooks::holdsRadio(next);
    if (!next) {
        clearW12BurstState();
        return false;
    }
    if (!nextEligible || nextHoldsRadio) {
        if (priorActive)
            cancelW12Burst();
        else
            clearW12BurstState();
        return false;
    }

    // Capture the deadline that notifyLater actually accepted. _cached_next_run is the protected
    // request deadline set by notifyLater. OSThread::run later rebases the actual deadline on
    // callback return, so this diagnostic includes that callback tail and owner dispatch delay.
    // It is not lateness relative to the final scheduler deadline. Rejection creates no sample,
    // and stale callbacks are filtered by timerPending in onNotify().
    const bool scheduled = notifyLater(W12_BURST_GUARD_MS, W12_BURST_DELAY_COMPLETED, false);
    if (!scheduled) {
        if (w12BenchmarkModule)
            w12BenchmarkModule->onW12BurstAborted();
        clearW12BurstState();
        return false;
    }

    w12Burst.active = true;
    w12Burst.timerPending = true;
    w12Burst.completedFrames = completedFrames;
    w12Burst.nextPacket = next;
    w12Burst.nextPacketId = next->id;
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    w12Burst.guardDueAtMs = static_cast<uint32_t>(_cached_next_run);
#endif
    // A newly accepted guarded event proves that no displaced stale event is
    // occupying the notification slot, so an old abort/reconfigure resume
    // marker cannot affect this fresh sequence.
    w12BurstResumeAfterStale = false;
    if (w12BenchmarkModule) {
        // The initial accepted guard owns completion of the first frame. Each
        // later successful guarded send is counted exactly once at its ISR_TX
        // completion above.
        if (!priorActive)
            w12BenchmarkModule->onW12BurstFrame();
        w12BenchmarkModule->onW12BurstArmed(!priorActive);
    }
    return true;
}
#endif

void RadioLibInterface::scheduleIrqPollTick()
{
    // Never overwrite a pending notification (especially TRANSMIT_DELAY_COMPLETED),
    // otherwise poll ticks would starve TX scheduling.
    //
    // There is a single notification slot, so while a TX is queued and the radio is busy receiving,
    // the self-rescheduling TRANSMIT_DELAY_COMPLETED timer (which does overwrite, see txTimerOverwrite)
    // can keep the slot and prevent a poll tick from being scheduled. In that window a completing
    // RX/TX is not seen by the poll; RadioInterface's pollMissedIrqs() (~1s) is the backup that
    // recovers it, so the effect is bounded added latency under heavy contention, not a lost event.
    notifyLater(1, ISR_POLL_TICK, false);
}

void RadioLibInterface::deliverPendingIrqFromPoll(PendingISR cause)
{
    disableInterrupt(); // stop polling; this is the poll-path equivalent of isrLevel0Common()
    notify(cause, true);
}

void RadioLibInterface::onNotify(uint32_t notification)
{

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
    const uint32_t ownerRxNotifyAtUs = notification == ISR_RX ? static_cast<uint32_t>(micros()) : 0;
    const uint32_t ownerRxDoneBefore =
        notification == ISR_RX && w12BenchmarkModule ? w12BenchmarkModule->getRadioRxDoneCount() : 0;
    const uint32_t ownerRxArmFailuresBefore =
        notification == ISR_RX && w12BenchmarkModule ? w12BenchmarkModule->getRadioRxArmFailureCount() : 0;
    const uint32_t ownerTxNotifyAtUs = notification == ISR_TX ? static_cast<uint32_t>(micros()) : 0;
#endif

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
#if !(MESHTASTIC_W12_BENCHMARK_TX_BURST)
    if (w12BenchmarkModule)
        w12BenchmarkModule->onTxDelayNotification(notification == TRANSMIT_DELAY_COMPLETED, txQueue.getFront());
#else
    if (w12BenchmarkModule && notification != W12_BURST_DELAY_COMPLETED)
        w12BenchmarkModule->onTxDelayNotification(notification == TRANSMIT_DELAY_COMPLETED, txQueue.getFront());
#endif
#endif

    switch (notification) {
    case ISR_TX: {
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
        // A poll-generated TX notification can remain latched while standby drains another
        // notification. With no active packet it is stale. If it displaced a live guarded
        // event, restore the ordinary RX/CCA handoff immediately because that one-slot event
        // is gone. Explicit standby keeps the inert behavior by suppressing this handoff.
        if (!sendingPacket) {
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
            if (w12BenchmarkModule)
                w12BenchmarkModule->onOwnerTxNotification(ownerTxNotifyAtUs, false, false);
#endif
            const bool normalHandoffRequired = w12Burst.active || w12Burst.timerPending || w12BurstResumeAfterStale;
            const bool ordinaryHandoffRequired = isReceiving && !txQueue.empty();
            if (w12BurstArmSuppressed)
                cancelW12Burst();
            else if (normalHandoffRequired)
                finishW12BurstToNormal();
            else if (ordinaryHandoffRequired)
                setTransmitDelay();
            else
                cancelW12Burst();
            break;
        }
        // Capture burst eligibility before handleTransmitInterrupt(); owner TX attribution runs inside it before
        // completion releases the packet and its owner slot.
        const bool completedPacketEligible = isW12BurstPacket(sendingPacket);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
        const bool transmitSucceeded = handleTransmitInterrupt(&ownerTxNotifyAtUs);
#else
        const bool transmitSucceeded = handleTransmitInterrupt();
#endif
        if (transmitSucceeded && !w12BurstArmSuppressed && armW12BurstAfterSuccess(completedPacketEligible))
            break;
        cancelW12Burst();
        // Explicit standby drains the completion but must leave the next
        // packet queued. Do not replace the drained TX_DONE with an ordinary
        // timer that could wake the radio after standby returns.
        if (w12BurstArmSuppressed)
            break;
#else
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
        handleTransmitInterrupt(&ownerTxNotifyAtUs);
#else
        handleTransmitInterrupt(); // completeSending() already restored the radio to the home config
#endif
#endif
        // Let the hooks pre-stage the radio for the NEXT queued packet. Not required for correctness -
        // TRANSMIT_DELAY_COMPLETED asks again before the scan, which is where the answer is acted on -
        // but it keeps the post-TX listen window on the channel we are about to transmit on.
        (void)RadioTxHooks::beforeTransmit(this, txQueue.getFront());
        startReceive();
        setTransmitDelay();
        break;
    }
    case ISR_RX:
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
        cancelW12Burst();
#endif
        handleReceiveInterrupt();
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
        if (w12BurstArmSuppressed) {
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
            if (w12BenchmarkModule)
                w12BenchmarkModule->onOwnerRxNotification(ownerRxNotifyAtUs, static_cast<uint32_t>(micros()), ownerRxDoneBefore,
                                                          w12BenchmarkModule->getRadioRxDoneCount(), ownerRxArmFailuresBefore,
                                                          w12BenchmarkModule->getRadioRxArmFailureCount(), false);
#endif
            break;
        }
#endif
        startReceive();
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
        if (w12BenchmarkModule)
            w12BenchmarkModule->onOwnerRxNotification(ownerRxNotifyAtUs, static_cast<uint32_t>(micros()), ownerRxDoneBefore,
                                                      w12BenchmarkModule->getRadioRxDoneCount(), ownerRxArmFailuresBefore,
                                                      w12BenchmarkModule->getRadioRxArmFailureCount(), isReceiving && !rxOffline);
#endif
        setTransmitDelay();
        break;
    case ISR_POLL_TICK:
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
        if (w12Burst.timerPending) {
            finishW12BurstToNormal();
            break;
        }
#endif
        handleSoftwareLoraIrqPoll();
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
        // The poll can discover TX_DONE and replace its own notification with ISR_TX.
        // Drain that completion while suppression is still active so ISR_TX cannot
        // schedule an ordinary timer after standby has released the packet.
        if (w12BurstArmSuppressed)
            checkNotification();
#endif
        break;
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
    case W12_BURST_DELAY_COMPLETED: {
        if (!w12Burst.timerPending) {
            // Reconfigure cannot remove the one-slot timer. Once it has armed ordinary RX,
            // let a displaced ordinary sender recover its normal timer. Standby explicitly
            // leaves this flag clear so a stale event cannot wake the radio.
            const bool resumeNormalTx = w12BurstResumeAfterStale;
            w12BurstResumeAfterStale = false;
            if (resumeNormalTx && !disabled && RadioMode::canTransmit() && isReceiving && !sendingPacket && !txQueue.empty())
                setTransmitDelay();
            break;
        }

        // Only a live dedicated callback has a valid due time. Stale callbacks return above and
        // never enter this measurement path.
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
        if (w12BenchmarkModule)
            w12BenchmarkModule->onW12BurstGuardLateness(Time::getMillis(), w12Burst.guardDueAtMs);
#endif
        w12Burst.timerPending = false;
        meshtastic_MeshPacket *next = txQueue.getFront();
        const bool samePacket = next && next == w12Burst.nextPacket && next->id == w12Burst.nextPacketId;
        if (!samePacket || !isW12BurstPacket(next) || RadioTxHooks::holdsRadio(next)) {
            finishW12BurstToNormal();
            break;
        }

        const RadioTxHook::PreTxAction action = RadioTxHooks::beforeTransmit(this, next);
        if (action == RadioTxHook::PRETX_DEFER) {
            finishW12BurstToNormal();
            break;
        }
        if (action == RadioTxHook::PRETX_DROP) {
            meshtastic_MeshPacket *bad = txQueue.dequeue();
            if (bad) {
                notifyTxFinished(bad, TxState::Dropped);
                RadioTxHooks::packetReleased(this, bad);
                packetPool.release(bad);
            }
            finishW12BurstToNormal();
            break;
        }

        next = txQueue.getFront();
        if (!next || next != w12Burst.nextPacket || next->id != w12Burst.nextPacketId || !isW12BurstPacket(next) ||
            RadioTxHooks::holdsRadio(next)) {
            finishW12BurstToNormal();
            break;
        }

        bool prepared;
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
        if (w12BenchmarkModule) {
            const uint32_t prepareStartedAtUs = micros();
            prepared = prepareW12BurstSend();
            w12BenchmarkModule->onW12BurstPrepareDuration(static_cast<uint32_t>(micros() - prepareStartedAtUs), prepared);
        } else {
            prepared = prepareW12BurstSend();
        }
#else
        prepared = prepareW12BurstSend();
#endif
        if (!prepared) {
            finishW12BurstToNormal();
            break;
        }

        meshtastic_MeshPacket *txp = txQueue.dequeue();
        if (!txp || !startSend(txp)) {
            cancelW12Burst();
            if (!disabled && !isReceiving)
                startReceive();
            setTransmitDelay();
        }
        break;
    }
#endif
    case TRANSMIT_DELAY_COMPLETED:
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && MESHTASTIC_W12_BENCHMARK_TX_BURST
        // A regular event displaced the guarded event. Resume through ordinary CCA/backoff.
        cancelW12Burst();
        if (w12BurstArmSuppressed)
            break;
#endif
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule && !txQueue.empty())
            w12BenchmarkModule->onTxDelayFired(txQueue.getFront());
#endif

        // If we are not currently in receive mode, then restart the random delay (this can happen if the main thread
        // has placed the unit into standby)  FIXME, how will this work if the chipset is in sleep mode?
        if (!txQueue.empty()) {
            if (!canSendImmediately()) {
                setTransmitDelay(); // currently Rx/Tx-ing: reset random delay
            } else {
                meshtastic_MeshPacket *txp = txQueue.getFront();
                assert(txp);
                const uint32_t now = Time::getMillis();
                // Not `long remaining = tx_after - Time::getMillis()`: that uint32_t subtraction widens to
                // ~4.29e9 where long is 64-bit (portduino), rescheduling a due packet ~49.7 days out.
                if (txp->tx_after && !Throttle::deadlinePassedAt(now, txp->tx_after)) {
                    // There's still some delay pending on this packet, so resume waiting for it to elapse
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
                    const bool scheduled = notifyLater(txp->tx_after - now, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite);
                    if (w12BenchmarkModule)
                        w12BenchmarkModule->onTxDelayScheduled(txp, scheduled, txp->tx_after);
#else
                    notifyLater(txp->tx_after - now, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite);
#endif
                } else if (const RadioTxHook::PreTxAction action = RadioTxHooks::beforeTransmit(this, txp);
                           action == RadioTxHook::PRETX_DROP) {
                    // A module refuses this packet on the radio config we are holding: drop it rather
                    // than transmit it, and move on to the next queued packet.
                    meshtastic_MeshPacket *bad = txQueue.dequeue();
                    LOG_DEBUG("Drop Tx packet 0x%08x, refused before transmit", bad->id);
                    notifyTxFinished(bad, TxState::Dropped);
                    RadioTxHooks::packetReleased(this, bad);
                    packetPool.release(bad);
                    setTransmitDelay();
                } else if (action == RadioTxHook::PRETX_DEFER) {
                    setTransmitDelay(); // the radio config moved, so re-run the delay and scan on it
                } else {
                    bool channelActive;
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
                    if (w12BenchmarkModule) {
                        const uint32_t phaseStartedAt = micros();
                        channelActive = isChannelActive();
                        w12BenchmarkModule->onRadioPhase(W12BenchmarkModule::RadioPhase::CHANNEL_ACTIVE,
                                                         static_cast<uint32_t>(micros() - phaseStartedAt));
                    } else {
                        channelActive = isChannelActive();
                    }
#else
                    channelActive = isChannelActive();
#endif
                    if (channelActive) {
                        // Passive observations leave RX armed; restarting would discard the packet just detected.
                        if (!isReceiving && !RadioTxHooks::holdsRadio(txp)) {
                            startReceive();
                        }
                        setTransmitDelay();
                    } else {
                        // Send any outgoing packets we have ready as fast as possible to keep the time between channel scan and
                        // actual transmission as short as possible
                        txp = txQueue.dequeue();
                        assert(txp);
                        if (!startSend(txp))
                            setTransmitDelay();
                        LOG_TRACE("%d packets in TX queue", txQueue.getMaxLen() - txQueue.getFree());
                    }
                }
            }
        } else {
            // Do nothing, because the queue is empty
        }
        break;
    default:
        assert(0); // We expected to receive a valid notification from the ISR
    }
}

void RadioLibInterface::setTransmitDelay()
{
    meshtastic_MeshPacket *p = txQueue.getFront();
    if (!p) {
        return; // noop if there's nothing in the queue
    }

    // We want all sending/receiving to be done by our daemon thread.
    // We use a delay here because this packet might have been sent in response to a packet we just received.
    // So we want to make sure the other side has had a chance to reconfigure its radio.

    if (p->tx_after) {
        unsigned long add_delay = p->rx_rssi ? getTxDelayMsecWeighted(p) : getTxDelayMsec();
        unsigned long now = Time::getMillis();
        // skipZero, not timerEndsAtMillis: this is a clamp of three candidates rather than a plain
        // now + delay, and `if (p->tx_after)` above is the read that takes 0 as "no delay wanted" -
        // so a recomputation landing on 0 drops the CSMA backoff and the packet goes out at once.
        //
        // Narrow to uint32_t BEFORE skipZero, not after: add_delay is unsigned long, 64-bit on the
        // portduino host, so the clamp can exceed UINT32_MAX there. skipZero on the wide value would
        // pass 0x100000000 through as non-zero and the store to this uint32_t field would truncate it
        // back to the 0 being avoided.
        p->tx_after = Time::skipZero(
            (uint32_t)min(max(p->tx_after + add_delay, now + add_delay), now + 2 * getTxDelayMsecWeightedWorst(p->rx_snr)));
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        const bool scheduled = notifyLater(p->tx_after - now, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite);
        if (w12BenchmarkModule)
            w12BenchmarkModule->onTxDelayScheduled(p, scheduled, p->tx_after);
#else
        notifyLater(p->tx_after - now, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite);
#endif
    } else if (p->rx_snr == 0 && p->rx_rssi == 0) {
        /* We assume if rx_snr = 0 and rx_rssi = 0, the packet was generated locally.
         *   This assumption is valid because of the offset generated by the radio to account for the noise
         *   floor.
         */
        startTransmitTimer(true);
    } else {
        // If there is a SNR, start a timer scaled based on that SNR.
        LOG_TRACE("rx_snr found. hop_limit:%d rx_snr:%f", p->hop_limit, p->rx_snr);
        startTransmitTimerRebroadcast(p);
    }
}

void RadioLibInterface::startTransmitTimer(bool withDelay)
{
    // If we have work to do and the timer wasn't already scheduled, schedule it now
    if (!txQueue.empty()) {
        uint32_t delay = !withDelay ? 1 : getTxDelayMsec();
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        const uint32_t dueAtMs = Time::timerEndsAtMillis(delay);
        const bool scheduled = notifyLater(delay, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite); // This will implicitly enable
        if (w12BenchmarkModule)
            w12BenchmarkModule->onTxDelayScheduled(txQueue.getFront(), scheduled, dueAtMs);
#else
        notifyLater(delay, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite); // This will implicitly enable
#endif
    }
}

void RadioLibInterface::startTransmitTimerRebroadcast(meshtastic_MeshPacket *p)
{
    // If we have work to do and the timer wasn't already scheduled, schedule it now
    if (!txQueue.empty()) {
        uint32_t delay = getTxDelayMsecWeighted(p);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        const uint32_t dueAtMs = Time::timerEndsAtMillis(delay);
        const bool scheduled = notifyLater(delay, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite); // This will implicitly enable
        if (w12BenchmarkModule)
            w12BenchmarkModule->onTxDelayScheduled(p, scheduled, dueAtMs);
#else
        notifyLater(delay, TRANSMIT_DELAY_COMPLETED, txTimerOverwrite); // This will implicitly enable
#endif
    }
}

/**
 * If the packet is not already in the late rebroadcast window, move it there
 */
void RadioLibInterface::clampToLateRebroadcastWindow(NodeNum from, PacketId id)
{
    // Look for non-late packets only, so we don't do this twice!
    meshtastic_MeshPacket *p = txQueue.remove(from, id, true, false);
    if (p) {
        p->tx_after = Time::timerEndsAtMillis(getTxDelayMsecWeightedWorst(p->rx_snr));
        bool dropped = false;
        meshtastic_MeshPacket *evicted = nullptr;
        const bool accepted = txQueue.enqueue(p, &dropped, &evicted);
        if (evicted) {
            notifyTxFinished(evicted, TxState::Dropped);
            RadioTxHooks::packetReleased(this, evicted);
            packetPool.release(evicted);
        }
        if (accepted) {
            LOG_TRACE("Move queued packet to late rebroadcast window %ums from now", (uint32_t)(p->tx_after - millis()));
        } else {
            notifyTxFinished(p, TxState::Rejected);
            RadioTxHooks::packetReleased(this, p);
            packetPool.release(p);
        }
        if (dropped) {
            txDrop++;
        }
    }
}

/**
 * If there is a packet pending TX in the queue with a worse hop limit, remove it pending replacement with a better version
 * @return Whether a pending packet was removed
 */
bool RadioLibInterface::removePendingTXPacket(NodeNum from, PacketId id, uint32_t hop_limit_lt)
{
    meshtastic_MeshPacket *p = txQueue.remove(from, id, true, true, hop_limit_lt);
    if (p) {
        LOG_DEBUG("Drop pending-TX packet 0x%08x, hop limit %d", p->id, p->hop_limit);
        notifyTxFinished(p, TxState::Cancelled);
        RadioTxHooks::packetReleased(this, p);
        packetPool.release(p);
        return true;
    }
    return false;
}

bool RadioLibInterface::handleTransmitInterrupt(const uint32_t *ownerTxNotifyAtUs)
{
#if !(MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)))
    (void)ownerTxNotifyAtUs;
#endif
    // This can be null if we forced the device to enter standby mode.  In that case
    // ignore the transmit interrupt
    bool success = false;
    if (sendingPacket) {
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
        const bool ownerTxPacketOwned = w12BenchmarkModule && w12BenchmarkModule->ownsTx(sendingPacket);
#endif
        success = validTransmitIrq();
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
        if (!success && w12BenchmarkModule)
            w12BenchmarkModule->onTxFailureObserved(sendingPacket, W12BenchmarkModule::TxFailureStage::TX_IRQ, INT16_MIN);
        if (ownerTxNotifyAtUs && w12BenchmarkModule)
            w12BenchmarkModule->onOwnerTxNotification(*ownerTxNotifyAtUs, ownerTxPacketOwned, success);
#endif
        completeSending(success);
    }
    powerMon->clearState(meshtastic_PowerMon_State_Lora_TXOn); // But our transmitter is definitely off now
    return success;
}

void RadioLibInterface::completeSending(bool success)
{
    // We are careful to clear sending packet before calling printPacket because
    // that can take a long time
    auto p = sendingPacket;
    const uint32_t generation = sendingTxGeneration;
    sendingPacket = NULL;
    sendingTxGeneration = 0;
#ifdef LED_LORA
    digitalWrite(LED_LORA, LED_STATE_OFF);
#endif

    if (p) {
        // Packet has been sent, count it toward our TX airtime utilization.
        uint32_t xmitMsec = getPacketTime(p);
        airTime->logAirtime(TX_LOG, xmitMsec);

        if (success) {
            txGood++;
            if (!isFromUs(p))
                txRelay++;
        } else {
            txDrop++;
            RECORD_CRITICALERROR(meshtastic_CriticalErrorCode_TRANSMIT_FAILED);
        }
        notifyTxFinished(p, success ? TxState::Sent : TxState::Failed, generation);
        printPacket(success ? "Completed sending" : "Failed sending", p);
        // Keep this inside `if (p)`: completeSending() also runs on every setStandby(), where a hook
        // undoing its own pre-TX switch would recurse back through reconfigure().
        RadioTxHooks::packetReleased(this, p);

        // We are done sending that packet, release it
        packetPool.release(p);
    }
}

void RadioLibInterface::handleReceiveInterrupt()
{
    // when this is called, we should be in receive mode - if we are not, just jump out instead of bombing. Possible Race
    // Condition?
    if (!isReceiving) {
        LOG_ERROR("handleReceiveInterrupt called while not in rx mode");
        return;
    }

    isReceiving = false;
    if (!validReceiveIrq()) {
        rxBad++;
        return;
    }

    // read the number of actually received bytes
    size_t length = iface->getPacketLength();

    // Some drivers report this as a 16 bit value, so a bad readback can overrun radioBuffer in readData()
    if (length == 0 || length > MAX_LORA_PAYLOAD_LEN || length > sizeof(radioBuffer)) {
        LOG_ERROR("Ignore rx packet, bad length %u", (unsigned int)length);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onRxRead(false);
#endif
        rxBad++;
        return;
    }

    uint32_t rxMsec = getPacketTime(length, true);

#ifndef DISABLE_WELCOME_UNSET
    if ((RadioMode::isFlrc() ? RadioMode::activeConfig().region : config.lora.region) ==
        meshtastic_Config_LoRaConfig_RegionCode_UNSET) {
        LOG_WARN("lora rx disabled: Region unset");
        airTime->logAirtime(RX_ALL_LOG, rxMsec);
        return;
    }
#endif

    int state = iface->readData((uint8_t *)&radioBuffer, length);
#if ARCH_PORTDUINO
    if (portduino_config.logoutputlevel == level_trace) {
        printBytes("Raw incoming packet: ", (uint8_t *)&radioBuffer, length);
    }
#endif
    if (state != RADIOLIB_ERR_NONE) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onRxRead(false);
#endif
        // Log PacketHeader similar to RadioInterface::printPacket so we can try to match RX errors to other packets in the logs.
        LOG_ERROR("Ignore rx packet, error=%d (maybe id=0x%08x fr=0x%08x to=0x%08x flags=0x%02x rxSNR=%g rxRSSI=%i "
                  "nextHop=0x%x relay=0x%x)",
                  state, radioBuffer.header.id, radioBuffer.header.from, radioBuffer.header.to, radioBuffer.header.flags,
                  iface->getSNR(), lround(iface->getRSSI()), radioBuffer.header.next_hop, radioBuffer.header.relay_node);
        rxBad++;

        airTime->logAirtime(RX_ALL_LOG, rxMsec);

    } else {
        // Skip the 4 headers that are at the beginning of the rxBuf
        int32_t payloadLen = length - sizeof(PacketHeader);

        // check for short packets
        if (payloadLen < 0) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
            if (w12BenchmarkModule)
                w12BenchmarkModule->onRxRead(false);
#endif
            LOG_WARN("Ignore received packet too short");
            rxBad++;
            airTime->logAirtime(RX_ALL_LOG, rxMsec);
        } else {
            rxGood++;
            // altered packet with "from == 0" can do Remote Node Administration without permission
            if (radioBuffer.header.from == 0) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
                if (w12BenchmarkModule)
                    w12BenchmarkModule->onRxRead(false);
#endif
                LOG_WARN("Ignore received packet without sender");
                return;
            }

            // Note: we deliver _all_ packets to our router (i.e. our interface is intentionally promiscuous).
            // This allows the router and other apps on our node to sniff packets (usually routing) between other
            // nodes.
            meshtastic_MeshPacket *mp = packetPool.allocZeroed();
            if (!mp) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
                if (w12BenchmarkModule)
                    w12BenchmarkModule->onRxRead(false);
#endif
                airTime->logAirtime(RX_LOG, rxMsec);
                return;
            }
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
            if (w12BenchmarkModule)
                w12BenchmarkModule->onRxRead(true);
#endif

            // Keep the assigned fields in sync with src/mqtt/MQTT.cpp:onReceiveProto
            mp->from = radioBuffer.header.from;
            mp->to = radioBuffer.header.to;
            mp->id = radioBuffer.header.id;
            mp->channel = radioBuffer.header.channel;
            assert(HOP_MAX <= PACKET_FLAGS_HOP_LIMIT_MASK); // If hopmax changes, carefully check this code
            mp->hop_limit = radioBuffer.header.flags & PACKET_FLAGS_HOP_LIMIT_MASK;
            mp->hop_start = (radioBuffer.header.flags & PACKET_FLAGS_HOP_START_MASK) >> PACKET_FLAGS_HOP_START_SHIFT;
            mp->want_ack = !!(radioBuffer.header.flags & PACKET_FLAGS_WANT_ACK_MASK);
            mp->via_mqtt = !!(radioBuffer.header.flags & PACKET_FLAGS_VIA_MQTT_MASK);
            // If hop_start is not set, next_hop and relay_node are invalid (firmware <2.3)
            mp->next_hop = mp->hop_start == 0 ? NO_NEXT_HOP_PREFERENCE : radioBuffer.header.next_hop;
            mp->relay_node = mp->hop_start == 0 ? NO_RELAY_NODE : radioBuffer.header.relay_node;

            addReceiveMetadata(mp);

            mp->which_payload_variant =
                meshtastic_MeshPacket_encrypted_tag; // Mark that the payload is still encrypted at this point
            assert(((uint32_t)payloadLen) <= sizeof(mp->encrypted.bytes));
            memcpy(mp->encrypted.bytes, radioBuffer.payload, payloadLen);
            mp->encrypted.size = payloadLen;

            printPacket("Lora RX", mp);

#ifdef LED_LORA
            loraRxPacketObservable.notifyObservers(mp->from);
#endif

            airTime->logAirtime(RX_LOG, rxMsec);

            deliverToReceiver(mp);
        }
    }
}

void RadioLibInterface::startReceive()
{
    isReceiving = true;
    // Drivers only reach here once the chip actually accepted the RX start, so the radio is alive again.
    // This is the sole place the recovery ladder is cleared - nothing short of an armed RX counts as fixed.
    rxOffline = false;
    chipRecoveryFailures = 0;
    powerMon->setState(meshtastic_PowerMon_State_Lora_RXOn);
}

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
bool RadioLibInterface::performW12RxRearm(W12RxRearmResult &result)
{
    result = W12RxRearmResult{};
    return false;
}
#endif

void RadioLibInterface::pollMissedIrqs()
{
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (w12BenchmarkModule)
        w12BenchmarkModule->onRadioPoll();
#endif
    // RadioLibInterface::enableInterrupt uses EDGE-TRIGGERED interrupts. Poll as a backup to catch missed edges.
    if (isReceiving) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        setW12DiagnosticPollContext(true);
#endif
        checkRxDoneIrqFlag();
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        setW12DiagnosticPollContext(false);
#endif
    }
    if (sendingPacket) {
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        setW12DiagnosticPollContext(true);
#endif
        checkTxDoneIrqFlag();
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        setW12DiagnosticPollContext(false);
#endif
    }
}

void RadioLibInterface::resetAGC()
{
    // Base implementation: no-op. Override in chip-specific subclasses.
}

void RadioLibInterface::periodicRadioMaintenance()
{
    // Every startReceive() call site is event-driven (RX/TX ISR, the CAD-busy branch, reconfigure), and a
    // radio left with RX off can no longer raise an RX interrupt - on a node with nothing to transmit
    // nothing would ever re-arm it. This periodic tick is that retry; maybeRecoverChipStateLoss() throttles.
    if (rxOffline) {
        LOG_WARN("Radio RX offline, retrying");
        if (maybeRecoverChipStateLoss())
            startReceive();
        return; // a chip just re-inited (or still dead) has no use for an AGC reset this tick
    }

    resetAGC();
}

bool RadioLibInterface::maybeRecoverChipStateLoss()
{
    // One attempt per window: the transient resets this recovers from need a single re-init, and a
    // chip that stays dead must not stall the TX/RX paths with a begin() attempt on every call
    if (lastChipRecoveryMs && Throttle::isWithinTimespanMs(lastChipRecoveryMs, 30 * 1000UL)) {
        LOG_DEBUG("Radio recovery suppressed, %us since the last attempt", (Time::getMillis() - lastChipRecoveryMs) / 1000);
        return false;
    }

    // The ladder counts re-arms, not re-inits: only RadioLibInterface::startReceive() clears the count, and
    // only once the chip really accepted RX. Judging the previous attempt here - a throttle window later,
    // after its retry - is what stops a begin() that succeeded while leaving RX dead from crediting itself.
    if (chipRecoveryFailures >= MAX_CHIP_RECOVERY_FAILURES && rebootAtMsec == 0) {
        // Attempts are a throttle window apart, so this is minutes of a provably deaf chip. begin() alone
        // clearly isn't reviving it; reboot to re-run init(), which redoes the power-on sequence it skips.
        LOG_ERROR("Radio still deaf after %u re-inits, rebooting", chipRecoveryFailures);
        rebootAtMsec = Time::timerEndsAtMillis(DEFAULT_REBOOT_SECONDS * 1000);
    }
    chipRecoveryFailures++;

    lastChipRecoveryMs = Time::skipZero(Time::getMillis());
    RECORD_CRITICALERROR(meshtastic_CriticalErrorCode_INVALID_RADIO_SETTING);
    LOG_ERROR("Radio chip state lost mid-operation, re-init");
    bool recovered = recoverChipStateLoss();
    LOG_INFO("Radio re-init %s", recovered ? "succeeded" : "failed");
    return recovered;
}

void RadioLibInterface::checkRxDoneIrqFlag()
{
    if (receiveIrqPending()) {
        LOG_WARN("caught missed RX_DONE");
        notify(ISR_RX, true);
    }
}

void RadioLibInterface::checkTxDoneIrqFlag()
{
    const bool pending = iface->checkIrq(RADIOLIB_IRQ_TX_DONE);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    if (w12DiagnosticPollContext && w12BenchmarkModule)
        w12BenchmarkModule->onRadioPollTx(pending);
#endif
    if (pending) {
        LOG_WARN("caught missed TX_DONE");
        notify(ISR_TX, true);
    }
}

void RadioLibInterface::configHardwareForSend()
{
    powerMon->setState(meshtastic_PowerMon_State_Lora_TXOn);
}

void RadioLibInterface::setStandby()
{
    // neither sending nor receiving
    powerMon->clearState(meshtastic_PowerMon_State_Lora_RXOn);
    powerMon->clearState(meshtastic_PowerMon_State_Lora_TXOn);
}

/** start an immediate transmit */
bool RadioLibInterface::startSend(meshtastic_MeshPacket *txp)
{
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    const uint32_t phaseStartedAt = micros();
#endif
    notifyTxStarted(txp);
    /* NOTE: Minimize the actions before startTransmit() to keep the time between
             channel scan and actual transmit as low as possible to avoid collisions. */
    if (disabled || !RadioMode::canTransmit()) {
        LOG_WARN("Drop Tx packet: radio Tx disabled");
        // Never reaches completeSending(), so any per-packet radio state has to be released here.
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
        if (w12BenchmarkModule)
            w12BenchmarkModule->onTxFailureObserved(txp, W12BenchmarkModule::TxFailureStage::PREFLIGHT, INT16_MIN);
#endif
        notifyTxFinished(txp, TxState::Failed);
        RadioTxHooks::packetReleased(this, txp);
        packetPool.release(txp);
        startReceive();
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onRadioPhase(W12BenchmarkModule::RadioPhase::START_SEND,
                                             static_cast<uint32_t>(micros() - phaseStartedAt));
#endif
        return false;
    } else {
        configHardwareForSend(); // must be after setStandby

        size_t numbytes = beginSending(txp);

        const bool fastIrq = armTransmitBeforeStart();
        int res = RADIOLIB_ERR_NONE;
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
        auto failureStage = W12BenchmarkModule::TxFailureStage::CLEAR_TX_IRQ;
#endif
        if (fastIrq) {
            // A complete FLRC frame can finish before startTransmit() returns.
            res = iface->clearIrqFlags(UINT32_MAX);
            if (res == RADIOLIB_ERR_NONE)
                enableInterrupt(isrTxLevel0);
        }
        // unset-sentinel-ok: sendingPacket is the armed flag, so 0 is a legal stamp.
        lastTxStart = Time::getMillis();
        if (res == RADIOLIB_ERR_NONE) {
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
            failureStage = W12BenchmarkModule::TxFailureStage::START_TRANSMIT;
            const bool ownerTxPacketOwned = w12BenchmarkModule && w12BenchmarkModule->ownsTx(txp);
            const uint32_t ownerTxStartAtUs = static_cast<uint32_t>(micros());
#endif
            res = iface->startTransmit((uint8_t *)&radioBuffer, numbytes);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
            if (w12BenchmarkModule)
                w12BenchmarkModule->onOwnerTxStartTransmitCall(ownerTxStartAtUs, ownerTxPacketOwned);
            if (w12BenchmarkModule)
                w12BenchmarkModule->onOwnerTxStartTransmitResult(res == RADIOLIB_ERR_NONE);
#endif
        }
        if (res != RADIOLIB_ERR_NONE) {
            LOG_ERROR("startTransmit failed, error=%d", res);
            RECORD_CRITICALERROR(meshtastic_CriticalErrorCode_RADIO_SPI_BUG);

            // This send failed, but make sure to 'complete' it properly
            disableInterrupt();
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING))
            if (w12BenchmarkModule)
                w12BenchmarkModule->onTxFailureObserved(sendingPacket, failureStage, static_cast<int16_t>(res));
#endif
            completeSending(false);
            powerMon->clearState(meshtastic_PowerMon_State_Lora_TXOn); // Transmitter off now
            startReceive(); // Restart receive mode (because startTransmit failed to put us in xmit mode)
        } else {
            // Must be done AFTER, starting transmit, because startTransmit clears (possibly stale) interrupt pending register
            // bits
            if (!fastIrq)
                enableInterrupt(isrTxLevel0);
            printPacket("Started Tx", txp);
            onTransmitStarted();
            checkTxDoneIrqFlag();
#ifdef LED_LORA
            digitalWrite(LED_LORA, LED_STATE_ON);
#endif
        }

        const bool sent = res == RADIOLIB_ERR_NONE;
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
        if (w12BenchmarkModule)
            w12BenchmarkModule->onRadioPhase(W12BenchmarkModule::RadioPhase::START_SEND,
                                             static_cast<uint32_t>(micros() - phaseStartedAt));
#endif
        return sent;
    }
}
