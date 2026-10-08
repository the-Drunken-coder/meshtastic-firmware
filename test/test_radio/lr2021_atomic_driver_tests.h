// Exercise the pinned LR2021 finite-RX consume API through actual reply bytes.
// Invalid modem, status, length and cleanup must never publish stale packet
// metadata or permit an unproven rearm. Both paranoid modes must check failures.

#pragma once
#include "../test_radiolib_drivers/RecordingHal.h"
#include <deque>

#include <RadioLib.h>

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace w12AtomicDriverTests
{
class AtomicRecordingHal : public ::RecordingHal
{
  public:
    std::deque<std::vector<uint8_t>> scriptedReplies;
    bool scriptedReplyUnderflow = false;
    bool scriptedReplyLengthMismatch = false;
    void scriptRead(std::vector<uint8_t> bytes) { scriptedReplies.push_back(std::move(bytes)); }
    void spiTransfer(uint8_t *out, size_t len, uint8_t *in) override
    {
        ::RecordingHal::spiTransfer(out, len, in);
        if (scriptedReplies.empty()) {
            // Never silently accept the parent HAL's default bytes. An empty
            // script is an unexpected transaction, not a successful reply.
            scriptedReplyUnderflow = true;
            return;
        }
        auto reply = std::move(scriptedReplies.front());
        scriptedReplies.pop_front();
        if (reply.empty())
            return; // Keep the parent HAL success status for a command phase.
        if (reply.size() != len)
            scriptedReplyLengthMismatch = true;
        for (size_t i = 0; i < len; i++)
            in[i] = i < reply.size() ? reply[i] : 0;
    }
};
using RecordingHal = AtomicRecordingHal;
inline RecordingHal &freshHal()
{
    static RecordingHal hal;
    hal.reset();
    hal.scriptedReplies.clear();
    hal.scriptedReplyUnderflow = false;
    hal.scriptedReplyLengthMismatch = false;
    return hal;
}

constexpr uint32_t rxDone = RADIOLIB_LR2021_IRQ_RX_DONE;
constexpr uint8_t standbyRcStatus2 = 0x01; // LR2021 stat2[2:0] = STDBY_RC
constexpr uint8_t rxStatus2 = 0x04;        // LR2021 stat2[2:0] = RX
constexpr uint8_t sleepStatus2 = 0x00;     // LR2021 stat2[2:0] = sleep
constexpr uint8_t unknownStatus2 = 0x07;   // LR2021 stat2[2:0] = outside the table

void scriptStatus(RecordingHal &hal, uint8_t stat1, uint8_t stat2, uint32_t irq = 0)
{
    hal.scriptRead({stat1, stat2, static_cast<uint8_t>(irq >> 24), static_cast<uint8_t>(irq >> 16),
                    static_cast<uint8_t>(irq >> 8), static_cast<uint8_t>(irq)});
}

void scriptCheckedStatus(RecordingHal &hal, uint8_t stat2, uint32_t irq = 0)
{
    scriptStatus(hal, 0x04, stat2, irq);
}

void scriptIrqSnapshot(RecordingHal &hal, uint8_t stat2, uint32_t irq = 0)
{
    // GET_AND_CLEAR_IRQ_STATUS is LR2021's command phase followed by a NOP
    // reply phase. The reply itself is Stat1, Stat2, IRQ[31:0].
    hal.scriptRead({});
    scriptCheckedStatus(hal, stat2, irq);
}

void scriptCommandRead(RecordingHal &hal, uint8_t value)
{
    // LRxxxx read commands are a write transaction followed by a read with a
    // two-byte status prefix. The draft keeps statusWidth at 16 around setup.
    hal.scriptRead({});
    hal.scriptRead({0x04, 0x00, value});
}

void scriptCommandReadFailure(RecordingHal &hal)
{
    hal.scriptRead({});
    hal.scriptRead({0x00, 0x00, 0x00});
}

void scriptCleanup(RecordingHal &hal, uint8_t stat2 = standbyRcStatus2)
{
    // Each destructive write deliberately skips RadioLib's optional check and
    // is followed by one explicit fresh status reply.
    hal.scriptRead({});
    scriptCheckedStatus(hal, stat2);
    hal.scriptRead({});
    scriptCheckedStatus(hal, stat2);
}

void scriptCleanupFromSnapshot(RecordingHal &hal, uint8_t modeStatus2, uint8_t freshStat1 = 0x04,
                               uint8_t freshStatus2 = standbyRcStatus2)
{
    if (modeStatus2 != standbyRcStatus2) {
        // Sleep must first be woken by the NOP used by standby(..., true).
        if (modeStatus2 == sleepStatus2)
            hal.scriptRead({});
        hal.scriptRead({});
        // SET_STANDBY uses SPIcommand(..., verify=true). In paranoid mode its
        // checkStatus callback consumes a separate six-byte status transfer;
        // the following explicit readFreshStatus is a second proof.
#if RADIOLIB_SPI_PARANOID
        scriptCheckedStatus(hal, standbyRcStatus2);
#endif
        scriptStatus(hal, freshStat1, freshStatus2);
        return;
    }
    scriptCleanup(hal, standbyRcStatus2);
}

void assertScriptedRepliesConsumed(const RecordingHal &hal)
{
    TEST_ASSERT_FALSE(hal.scriptedReplyUnderflow);
    TEST_ASSERT_FALSE(hal.scriptedReplyLengthMismatch);
    TEST_ASSERT_TRUE(hal.scriptedReplies.empty());
}

void assertSuccessfulCleanupWireContract(const RecordingHal &hal)
{
    const auto *fifo = hal.first(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO));
    const auto *irq = hal.first(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ));
    TEST_ASSERT_NOT_NULL(fifo);
    TEST_ASSERT_NOT_NULL(irq);
    const uint8_t clearFifo[] = {static_cast<uint8_t>(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO >> 8),
                                 static_cast<uint8_t>(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)};
    const uint8_t clearIrq[] = {
        static_cast<uint8_t>(RADIOLIB_LR2021_CMD_CLEAR_IRQ >> 8), static_cast<uint8_t>(RADIOLIB_LR2021_CMD_CLEAR_IRQ),
        static_cast<uint8_t>(RADIOLIB_LR2021_IRQ_ALL >> 24),      static_cast<uint8_t>(RADIOLIB_LR2021_IRQ_ALL >> 16),
        static_cast<uint8_t>(RADIOLIB_LR2021_IRQ_ALL >> 8),       static_cast<uint8_t>(RADIOLIB_LR2021_IRQ_ALL)};
    TEST_ASSERT_EQUAL_UINT32(sizeof(clearFifo), fifo->size());
    TEST_ASSERT_EQUAL_MEMORY(clearFifo, fifo->data(), sizeof(clearFifo));
    TEST_ASSERT_EQUAL_UINT32(sizeof(clearIrq), irq->size());
    TEST_ASSERT_EQUAL_MEMORY(clearIrq, irq->data(), sizeof(clearIrq));
    // A successful FIFO clear must be proved before issuing the all-IRQ clear.
    // Both pointers refer to elements of the same recorded transaction array.
    const size_t fifoIndex = fifo - hal.transactions.data();
    const size_t irqIndex = irq - hal.transactions.data();
    TEST_ASSERT_EQUAL_UINT32(fifoIndex + 2, irqIndex);
    const uint8_t freshStatus[] = {0, 0, 0, 0, 0, 0};
    TEST_ASSERT_EQUAL_UINT32(sizeof(freshStatus), (fifo + 1)->size());
    TEST_ASSERT_EQUAL_MEMORY(freshStatus, (fifo + 1)->data(), sizeof(freshStatus));
}

void scriptSuccessfulPacket(RecordingHal &hal, const std::vector<uint8_t> &payload, uint8_t modeStatus2 = standbyRcStatus2,
                            uint8_t rssiAverageRaw = 0x50, uint8_t rssiSyncRaw = 0x30, uint8_t syncWord = 0x10)
{
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
    scriptIrqSnapshot(hal, modeStatus2, rxDone);

    hal.scriptRead({});
    hal.scriptRead({0x04, 0x00, static_cast<uint8_t>(payload.size() >> 8), static_cast<uint8_t>(payload.size()), rssiAverageRaw,
                    rssiSyncRaw, syncWord});

    // READ_RX_FIFO returns Stat1, Stat2, Data in one transaction. Module's
    // status-width-zero stream copies buffIn[2..] into the payload buffer.
    std::vector<uint8_t> fifoReply = {0x04, 0x04};
    fifoReply.insert(fifoReply.end(), payload.begin(), payload.end());
    hal.scriptRead(std::move(fifoReply));

    scriptCleanup(hal, standbyRcStatus2);
}

void test_readFlrcPacket_rejects_null_outputs_before_radio_io()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    LR2021FlrcRxPacketStatus status;
    uint8_t actual[8] = {};
    TEST_ASSERT_TRUE(radio.readFlrcPacket(nullptr, sizeof(actual), &status) == RADIOLIB_ERR_NULL_POINTER);
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), nullptr) == RADIOLIB_ERR_NULL_POINTER);
    TEST_ASSERT_TRUE(hal.transactions.empty());
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_reuses_checked_type_status_and_exact_fifo_length()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    const std::vector<uint8_t> expected = {0x10, 0x20, 0x30, 0x40};
    scriptSuccessfulPacket(hal, expected);

    uint8_t actual[sizeof(expected)] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) == RADIOLIB_ERR_NONE);
    TEST_ASSERT_TRUE(std::memcmp(actual, expected.data(), expected.size()) == 0);
    TEST_ASSERT_TRUE(module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] == Module::BITS_16);
    TEST_ASSERT_TRUE(status.irqReadValid);
    TEST_ASSERT_TRUE(status.packetStatusReadValid);
    TEST_ASSERT_TRUE(status.modeReadValid);
    TEST_ASSERT_TRUE(status.mode == 1);
    TEST_ASSERT_TRUE(status.irqFlags == rxDone);
    TEST_ASSERT_TRUE(status.packetLength == expected.size());
    TEST_ASSERT_TRUE(status.rssiAverage == -80.0f);
    TEST_ASSERT_TRUE(status.rssiSync == -48.0f);
    TEST_ASSERT_TRUE(status.syncWord == 1);
    TEST_ASSERT_TRUE(status.rearmSafe);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_GET_PACKET_TYPE)) == 1);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_GET_AND_CLEAR_IRQ_STATUS)) == 1);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_GET_RX_PKT_LENGTH)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS)) == 1);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)) == 1);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)) == 1);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 1);
    TEST_ASSERT_TRUE(hal.transactions.size() == 11);
    assertScriptedRepliesConsumed(hal);
    assertSuccessfulCleanupWireContract(hal);
}

void test_readFlrcPacket_blocks_rearm_when_packet_type_read_fails()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandReadFailure(hal);

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) != RADIOLIB_ERR_NONE);
    TEST_ASSERT_TRUE(status.rearmBlocked);
    TEST_ASSERT_TRUE(!status.rearmSafe);
    TEST_ASSERT_TRUE(!status.cleanupAttempted);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_rejects_foreign_modem_before_flrc_status()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_LORA);

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) == RADIOLIB_ERR_WRONG_MODEM);
    TEST_ASSERT_TRUE(status.packetLength == 0);
    TEST_ASSERT_TRUE(status.rearmBlocked);
    TEST_ASSERT_TRUE(!status.rearmSafe);
    TEST_ASSERT_TRUE(!status.cleanupAttempted);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_never_clears_fifo_before_verified_standby()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
    scriptIrqSnapshot(hal, unknownStatus2, rxDone);
    // The optional write check succeeds, but the explicit fresh proof reports
    // an unknown mode, so no FIFO or IRQ clear is allowed.
    hal.scriptRead({});
#if RADIOLIB_SPI_PARANOID
    scriptCheckedStatus(hal, standbyRcStatus2);
#endif
    scriptCheckedStatus(hal, unknownStatus2);

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) != RADIOLIB_ERR_NONE);
    TEST_ASSERT_TRUE(!status.rearmSafe);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_rejects_zero_and_address_error_without_fifo_read()
{
    for (const uint32_t irq : {rxDone, static_cast<uint32_t>(rxDone | RADIOLIB_LR2021_IRQ_ADDR_ERROR)}) {
        RecordingHal &hal = freshHal();
        Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
        module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
        LR2021 radio(&module);
        scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
        scriptIrqSnapshot(hal, standbyRcStatus2, irq);
        if (irq == rxDone) {
            hal.scriptRead({});
            hal.scriptRead({0x04, 0x00, 0x00, 0x00, 0x50, 0x30, 0x10});
        }
        scriptCleanupFromSnapshot(hal, standbyRcStatus2);

        uint8_t actual[8] = {};
        LR2021FlrcRxPacketStatus status;
        TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) != RADIOLIB_ERR_NONE);
        TEST_ASSERT_TRUE(status.packetLength == 0);
        TEST_ASSERT_TRUE(status.rearmSafe);
        TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)) == 0);
        assertScriptedRepliesConsumed(hal);
    }
}

void test_readFlrcPacket_rejects_sleep_mode_without_consuming_stale_stats()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
    scriptIrqSnapshot(hal, sleepStatus2, rxDone);
    scriptCleanupFromSnapshot(hal, sleepStatus2);

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) != RADIOLIB_ERR_NONE);
    TEST_ASSERT_TRUE(status.packetLength == 0);
    TEST_ASSERT_TRUE(!status.packetStatusReadValid);
    TEST_ASSERT_TRUE(!status.rearmSafe);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_SET_STANDBY)) == 1);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_rejects_oversize_before_fifo_read()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
    scriptIrqSnapshot(hal, standbyRcStatus2, rxDone);
    hal.scriptRead({});
    hal.scriptRead({0x04, 0x00, 0x00, 0x05, 0x50, 0x30, 0x10});
    scriptCleanupFromSnapshot(hal, standbyRcStatus2);

    uint8_t actual[4] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) == RADIOLIB_ERR_PACKET_TOO_LONG);
    TEST_ASSERT_TRUE(status.packetLength == 0);
    TEST_ASSERT_TRUE(!status.packetStatusReadValid);
    TEST_ASSERT_TRUE(status.rearmSafe);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_rejects_rx_mode_before_fifo_and_defers_destructive_cleanup()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
    scriptIrqSnapshot(hal, rxStatus2, rxDone);
    // The paranoid-only SET_STANDBY check succeeds, but the mandatory fresh
    // status proof fails. Cleanup must stay unsafe and must not clear either
    // FIFO or IRQ state.
    scriptCleanupFromSnapshot(hal, rxStatus2, 0x00, standbyRcStatus2);

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    const int16_t result = radio.readFlrcPacket(actual, sizeof(actual), &status);
    TEST_ASSERT_TRUE(result == RADIOLIB_ERR_UNKNOWN);
    TEST_ASSERT_TRUE(status.mode == 4);
    TEST_ASSERT_TRUE(!status.rearmSafe);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_SET_STANDBY)) == 1);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO)) == 0);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_rejects_every_profile_error_irq()
{
    for (const uint32_t error : {RADIOLIB_LR2021_IRQ_CRC_ERROR, RADIOLIB_LR2021_IRQ_LEN_ERROR, RADIOLIB_LR2021_IRQ_ADDR_ERROR,
                                 RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR, RADIOLIB_LR2021_IRQ_TIMEOUT, RADIOLIB_LR2021_IRQ_ERROR,
                                 RADIOLIB_LR2021_IRQ_CMD_ERROR}) {
        RecordingHal &hal = freshHal();
        Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
        module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
        LR2021 radio(&module);
        scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
        scriptIrqSnapshot(hal, standbyRcStatus2, rxDone | error);
        scriptCleanupFromSnapshot(hal, standbyRcStatus2);

        uint8_t actual[8] = {};
        LR2021FlrcRxPacketStatus status;
        TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) != RADIOLIB_ERR_NONE);
        TEST_ASSERT_TRUE(status.rearmSafe);
        TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS)) == 0);
        TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_READ_RX_FIFO)) == 0);
        assertScriptedRepliesConsumed(hal);
    }
}

void test_readFlrcPacket_reports_cleanup_failure_as_rearm_unsafe()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
    scriptIrqSnapshot(hal, standbyRcStatus2, rxDone);
    hal.scriptRead({});
    hal.scriptRead({0x04, 0x00, 0x00, 0x04, 0x50, 0x30, 0x10});
    hal.scriptRead({0x04, standbyRcStatus2, 1, 2, 3, 4});
    // FIFO is read once, then CLEAR_RX_FIFO's fresh status fails. CLEAR_IRQ
    // is not attempted after an unproven FIFO teardown.
    hal.scriptRead({});
    hal.scriptRead({0x00, standbyRcStatus2, 0, 0, 0, 0});

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) != RADIOLIB_ERR_NONE);
    TEST_ASSERT_TRUE(status.packetLength == 0);
    TEST_ASSERT_TRUE(!status.packetStatusReadValid);
    TEST_ASSERT_TRUE(!status.rearmSafe);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_primary_crc_error_wins_cleanup_failure()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
    scriptIrqSnapshot(hal, standbyRcStatus2, rxDone | RADIOLIB_LR2021_IRQ_CRC_ERROR);
    hal.scriptRead({});
    hal.scriptRead({0x00, standbyRcStatus2, 0, 0, 0, 0});

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) == RADIOLIB_ERR_CRC_MISMATCH);
    TEST_ASSERT_TRUE(!status.rearmSafe);
    TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_readFlrcPacket_consecutive_frames_refresh_length_and_rssi()
{
    RecordingHal &hal = freshHal();
    Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
    LR2021 radio(&module);
    const std::vector<uint8_t> first = {0x01, 0x02};
    const std::vector<uint8_t> second = {0xA0, 0xB0, 0xC0, 0xD0, 0xE0};
    scriptSuccessfulPacket(hal, first, standbyRcStatus2, 0x50, 0x30, 0x10);
    scriptSuccessfulPacket(hal, second, standbyRcStatus2, 0x64, 0x20, 0x20);

    uint8_t actual[8] = {};
    LR2021FlrcRxPacketStatus status;
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) == RADIOLIB_ERR_NONE);
    TEST_ASSERT_TRUE(status.packetLength == first.size());
    TEST_ASSERT_TRUE(status.rssiAverage == -80.0f);
    TEST_ASSERT_TRUE(std::memcmp(actual, first.data(), first.size()) == 0);
    std::memset(actual, 0, sizeof(actual));
    TEST_ASSERT_TRUE(radio.readFlrcPacket(actual, sizeof(actual), &status) == RADIOLIB_ERR_NONE);
    TEST_ASSERT_TRUE(status.packetLength == second.size());
    TEST_ASSERT_TRUE(status.rssiAverage == -100.0f);
    TEST_ASSERT_TRUE(status.rssiSync == -32.0f);
    TEST_ASSERT_TRUE(status.syncWord == 2);
    TEST_ASSERT_TRUE(std::memcmp(actual, second.data(), second.size()) == 0);
    assertScriptedRepliesConsumed(hal);
}

void test_discardFlrcReceive_requires_successful_fifo_and_irq_cleanup()
{
    for (const bool failFifo : {true, false}) {
        RecordingHal &hal = freshHal();
        Module module(&hal, 1, RADIOLIB_NC, RADIOLIB_NC, 2);
        module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_16;
        LR2021 radio(&module);
        // discardFlrcReceive proves the modem afresh before taking this
        // destructive snapshot.
        scriptCommandRead(hal, RADIOLIB_LR2021_PACKET_TYPE_FLRC);
        scriptIrqSnapshot(hal, standbyRcStatus2);
        hal.scriptRead({});
        scriptCheckedStatus(hal, failFifo ? 0x00 : standbyRcStatus2);
        if (!failFifo) {
            hal.scriptRead({});
            scriptCheckedStatus(hal, 0x00);
        }

        LR2021FlrcRxDiscardStatus status;
        TEST_ASSERT_TRUE(radio.discardFlrcReceive(&status) != RADIOLIB_ERR_NONE);
        TEST_ASSERT_TRUE(status.standbyVerified);
        TEST_ASSERT_TRUE(status.fifoCleared == !failFifo);
        TEST_ASSERT_TRUE(status.irqCleared == false);
        TEST_ASSERT_TRUE(!status.rearmSafe);
        TEST_ASSERT_TRUE(hal.count(op16(RADIOLIB_LR2021_CMD_CLEAR_IRQ)) == (failFifo ? 0u : 1u));
        assertScriptedRepliesConsumed(hal);
    }
}
void runAtomicDriverTests()
{
    RUN_TEST(test_readFlrcPacket_rejects_null_outputs_before_radio_io);
    RUN_TEST(test_readFlrcPacket_reuses_checked_type_status_and_exact_fifo_length);
    RUN_TEST(test_readFlrcPacket_blocks_rearm_when_packet_type_read_fails);
    RUN_TEST(test_readFlrcPacket_rejects_foreign_modem_before_flrc_status);
    RUN_TEST(test_readFlrcPacket_never_clears_fifo_before_verified_standby);
    RUN_TEST(test_readFlrcPacket_rejects_zero_and_address_error_without_fifo_read);
    RUN_TEST(test_readFlrcPacket_rejects_sleep_mode_without_consuming_stale_stats);
    RUN_TEST(test_readFlrcPacket_rejects_oversize_before_fifo_read);
    RUN_TEST(test_readFlrcPacket_rejects_rx_mode_before_fifo_and_defers_destructive_cleanup);
    RUN_TEST(test_readFlrcPacket_rejects_every_profile_error_irq);
    RUN_TEST(test_readFlrcPacket_reports_cleanup_failure_as_rearm_unsafe);
    RUN_TEST(test_readFlrcPacket_primary_crc_error_wins_cleanup_failure);
    RUN_TEST(test_readFlrcPacket_consecutive_frames_refresh_length_and_rssi);
    RUN_TEST(test_discardFlrcReceive_requires_successful_fifo_and_irq_cleanup);
}
} // namespace w12AtomicDriverTests
