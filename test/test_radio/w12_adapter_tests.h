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
#include "NodeDB.h"
#include "PowerMon.h"
#include "Router.h"
#include "UptimeClock.h"
#include "airtime.h"
#include "modules/W12BenchmarkModule.h"

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
    uint16_t rssiHalfDbm = 220;
    unsigned interruptsArmed = 0;
    unsigned interruptsDisarmed = 0;
    uint32_t irqOnSetTx = 0;
    bool interruptArmed = false;
    bool interruptArmedAtSetTx = false;
    bool rawStatusFailed = false;
    uint8_t rawStatusMode = 0x04;
    unsigned rssiReads = 0;
    unsigned injectIrqAtRssiRead = 0;
    uint32_t irqOnRssiRead = 0;
    unsigned irqReads = 0;
    unsigned injectIrqAtRead = 0;
    uint32_t irqOnRead = 0;

    void signalReceive(uint32_t flags)
    {
        irq = flags;
        if ((flags & W12FlrcProfile::RECEIVE_IRQS) && interruptCallback)
            interruptCallback();
    }

    void pinMode(uint32_t, uint32_t) override {}
    void digitalWrite(uint32_t, uint32_t) override {}
    uint32_t digitalRead(uint32_t) override { return 0; }
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
        if (rssiReplyPending) {
            rssiReplyPending = false;
            if (++rssiReads == injectIrqAtRssiRead)
                signalReceive(irqOnRssiRead);
            in[0] = failCommand == RADIOLIB_LR2021_CMD_GET_RSSI_INST ? 0x02 : 0x04;
            in[1] = 0x04;
            in[2] = rssiHalfDbm >> 1;
            in[3] = (rssiHalfDbm & 1) << 7;
            return;
        }
        if (length >= 2) {
            uint16_t command = (uint16_t(out[0]) << 8) | out[1];
            if (command == RADIOLIB_LR2021_CMD_GET_RSSI_INST)
                rssiReplyPending = true;
            if (command == RADIOLIB_LR2021_CMD_CLEAR_IRQ && length >= 6) {
                uint32_t mask = (uint32_t(out[2]) << 24) | (uint32_t(out[3]) << 16) | (uint32_t(out[4]) << 8) | out[5];
                irq &= ~mask;
            }
            if (command == RADIOLIB_LR2021_CMD_SET_TX) {
                interruptArmedAtSetTx = interruptArmed;
                // Complete during the actual command; firmware must observe the IRQ after startTransmit returns.
                irq = irqOnSetTx;
            }
            if (failCommand && command == failCommand &&
                (failCommandOccurrence == 0 || ++failCommandSeen == failCommandOccurrence))
                in[0] = 0x02;
        }
        if (length == 6 && std::all_of(out, out + length, [](uint8_t b) { return b == 0; })) {
            if (++irqReads == injectIrqAtRead)
                signalReceive(irqOnRead);
            in[0] = rawStatusFailed ? 0x02 : 0x04;
            in[1] = rawStatusMode;
            in[2] = irq >> 24;
            in[3] = irq >> 16;
            in[4] = irq >> 8;
            in[5] = irq;
        }
    }

  private:
    bool rssiReplyPending = false;
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
    bool isOffline() const { return rxOffline; }
    bool receiving() const { return isReceiving; }
    uint32_t badReceives() const { return rxBad; }
    uint32_t goodTransmits() const { return txGood; }
    uint16_t droppedTransmits() const { return txDrop; }
    int16_t changeCrc(uint8_t bytes) { return lora.setCRC(bytes); }
    uint32_t driverDuration(size_t bytes) { return lora.getTimeOnAir(bytes); }
    void receiveInterrupt() { handleReceiveInterrupt(); }
    void transmitInterrupt() { handleTransmitInterrupt(); }
    size_t takeTransmission(meshtastic_MeshPacket *packet) { return beginSending(packet); }
    bool sendNow(meshtastic_MeshPacket *packet) { return startSend(packet); }
    void serviceNotifications() { checkNotification(); }
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

static W12AdapterHal *adapterHal;
static TestableW12Adapter *adapter;
static void makeW12Adapter();

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
class TestableW12AdapterDiagnostics : public W12BenchmarkModule
{
  public:
    using W12BenchmarkModule::handleReceived;
};

static constexpr NodeNum adapterDiagnosticSource = 0x11111111;
static constexpr NodeNum adapterDiagnosticDestination = 0x22222222;
static TestableW12AdapterDiagnostics *adapterDiagnostics;
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

static ProcessMessage sendAdapterDiagnosticControl(W12BenchmarkModule::Op op)
{
    TEST_ASSERT_NOT_NULL(adapterDiagnostics);
    TEST_ASSERT_NOT_NULL(adapterDiagnosticsNodeDB);
    meshtastic_MeshPacket control = meshtastic_MeshPacket_init_zero;
    control.from = 0;
    control.to = adapterDiagnosticDestination;
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
    adapter->pollMissedIrqs();
    TEST_ASSERT_EQUAL_UINT32(1, adapterReceiver->packets.size());
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
    adapter->stop();
    adapterHal->irqOnSetTx = 0;
    adapterHal->failCommand = RADIOLIB_LR2021_CMD_SET_TX;
    TEST_ASSERT_FALSE(adapter->sendNow(makeAdapterTransmission()));
    TEST_ASSERT_FALSE(adapter->isSending());
    TEST_ASSERT_TRUE(adapter->receiving());
    TEST_ASSERT_EQUAL_UINT32(0, adapter->goodTransmits());
    TEST_ASSERT_EQUAL_UINT16(2, adapter->droppedTransmits());
    TEST_ASSERT_EQUAL_INT32(liveBefore, packetPoolLiveBytes());
}
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

static void runW12AdapterTests()
{
    RUN_TEST(test_w12_adapter_recovery_preserves_active_flrc_and_rearms_rx);
    RUN_TEST(test_w12_adapter_failed_rx_remains_offline_until_successful_rearm);
    RUN_TEST(test_w12_adapter_sensing_busy_and_failed_reads_defer_without_lora_cad);
    RUN_TEST(test_w12_adapter_terminal_rx_error_rejects_payload_and_rearms);
    RUN_TEST(test_w12_adapter_failed_irq_status_keeps_channel_busy_and_rejects_stale_rx);
    RUN_TEST(test_w12_adapter_transmit_requires_tx_done_and_never_double_completes);
    RUN_TEST(test_w12_adapter_disabling_queued_tx_restores_receive);
    RUN_TEST(test_w12_adapter_busy_tx_delay_preserves_incoming_reception);
    RUN_TEST(test_w12_adapter_busy_tx_delay_preserves_rx_done_during_last_observation);
    RUN_TEST(test_w12_adapter_failed_observation_with_recovery_suppressed_preserves_rx_done);
    RUN_TEST(test_w12_adapter_failed_observation_defers_fresh_recovery_until_rx_done_is_delivered);
    RUN_TEST(test_w12_adapter_failed_observation_preserves_active_reception_and_later_completion);
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_successful_arm_stages);
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_standby_failure_and_result);
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_start_failure_retry_and_result);
    RUN_TEST(test_w12_adapter_radio_diagnostics_counts_irq_map_failure_and_result);
    RUN_TEST(test_w12_adapter_radio_diagnostics_poll_reads_raw_status_once);
    RUN_TEST(test_w12_adapter_radio_diagnostic_software_irq_state_tracks_standby_and_rx);
#endif
#if defined(MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX) && MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX
    RUN_TEST(test_w12_adapter_tx_attempt_tracks_queue_start_done_and_pool_reuse);
    RUN_TEST(test_w12_adapter_production_queue_eviction_reject_cancel_and_no_lora);
    RUN_TEST(test_w12_adapter_forced_standby_cannot_start_ack_wait);
    RUN_TEST(test_w12_adapter_short_send_arms_irq_before_set_tx_and_completes_immediately);
    RUN_TEST(test_w12_adapter_send_without_tx_done_times_out_and_releases_packet_once);
    RUN_TEST(test_w12_adapter_failed_irq_status_cannot_credit_stale_tx_done);
    RUN_TEST(test_w12_adapter_terminal_send_error_and_start_failure_release_without_success);
#else
    RUN_TEST(test_w12_adapter_default_gate_refuses_flrc_send_and_releases_packet);
#endif
}

#else
static void deleteW12Adapter() {}
static void runW12AdapterTests() {}
#endif
