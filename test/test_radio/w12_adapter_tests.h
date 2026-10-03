#pragma once

// LR2021Interface in src/mesh/LR2021Interface.cpp must restore FLRC after a radio fault,
// reject terminal RX errors before reading payloads, and count TX only after TX_DONE.
// These checks use the production adapter and pinned RadioLib driver with scripted SPI,
// guarding against adapter recovery falling into LoRa and failed sends crediting success.
#if ARCH_PORTDUINO && RADIOLIB_EXCLUDE_LR2021 != 1

#include "../test_radiolib_drivers/RecordingHal.h"
#include "LR2021Interface.h"
#include "PowerMon.h"
#include "UptimeClock.h"
#include "airtime.h"

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
    uint16_t rssiHalfDbm = 220;
    unsigned interruptsArmed = 0;
    unsigned interruptsDisarmed = 0;
    uint32_t irqOnSetTx = 0;
    bool interruptArmed = false;
    bool interruptArmedAtSetTx = false;
    bool rawStatusFailed = false;

    void pinMode(uint32_t, uint32_t) override {}
    void digitalWrite(uint32_t, uint32_t) override {}
    uint32_t digitalRead(uint32_t) override { return 0; }
    void attachInterrupt(uint32_t, void (*)(void), uint32_t) override
    {
        interruptsArmed++;
        interruptArmed = true;
    }
    void detachInterrupt(uint32_t) override
    {
        interruptsDisarmed++;
        interruptArmed = false;
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
            if (failCommand && command == failCommand)
                in[0] = 0x02;
        }
        if (length == 6 && std::all_of(out, out + length, [](uint8_t b) { return b == 0; })) {
            in[0] = rawStatusFailed ? 0x02 : 0x04;
            in[1] = 0x04;
            in[2] = irq >> 24;
            in[3] = irq >> 16;
            in[4] = irq >> 8;
            in[5] = irq;
        }
    }

  private:
    bool rssiReplyPending = false;
};

class TestableW12Adapter : public LR2021Interface
{
  public:
    explicit TestableW12Adapter(W12AdapterHal *hal) : LR2021Interface(hal, 1, 3, 4, 2) {}
    void armReceive() { startReceive(); }
    bool recover() { return recoverChipStateLoss(); }
    void stop() { setStandby(); }
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
};

static W12AdapterHal *adapterHal;
static TestableW12Adapter *adapter;
static AirTime *savedAdapterAirTime;
static PowerMon *savedAdapterPowerMon;

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
        delete adapter;
        adapter = nullptr;
        delete adapterHal;
        adapterHal = nullptr;
        delete airTime;
        airTime = savedAdapterAirTime;
        delete powerMon;
        powerMon = savedAdapterPowerMon;
    }
    Time::useRealClock();
}

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

#if defined(MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX) && MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX
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
#if defined(MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX) && MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX
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
