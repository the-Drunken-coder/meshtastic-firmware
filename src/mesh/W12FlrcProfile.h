#pragma once

#include <RadioLib.h>
#if RADIOLIB_EXCLUDE_LR2021 != 1
#include "../../variants/esp32s3/meshnology-w12/W12RfSwitch.h"
#endif

// Candidate validated by the standalone W12 bench at RadioLib 510e00cf. Board RF acceptance is pending.
namespace W12FlrcProfile
{
constexpr float FREQUENCY_MHZ = 915.0f;
constexpr uint16_t BIT_RATE_KBPS = 1040;
constexpr int8_t CHIP_POWER_DBM = -9;
constexpr uint16_t PREAMBLE_BITS = 32;
constexpr uint8_t CRC_BYTES = 4;
#if MESHTASTIC_W12_BENCHMARK && defined(MESHTASTIC_W12_BENCHMARK_SLOT_MS)
constexpr uint32_t SLOT_MS = MESHTASTIC_W12_BENCHMARK_SLOT_MS;
static_assert(SLOT_MS <= 10, "Diagnostic slot must stay within the bounded experiment");
#else
constexpr uint32_t SLOT_MS = 10;
#endif
constexpr uint32_t TURNAROUND_MS = 2;
constexpr uint32_t COMPLETION_ALLOWANCE_US = 3000;
constexpr uint32_t TX_TIMEOUT_MS = 100;
#if (MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) && defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS)
#if defined(MESHTASTIC_W12_BENCHMARK_SINGLE_RX) && MESHTASTIC_W12_BENCHMARK_SINGLE_RX
#error "MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS cannot be combined with single RX"
#endif
// SetRx uses 24-bit periods of the LR2021's 32.768 kHz RTC. 0xFFFFFF is reserved for continuous RX.
constexpr uint32_t RX_TIMEOUT_RTC_HZ = 32768;
constexpr uint32_t RX_TIMEOUT_MAX_TICKS = 0xFFFFFEUL;
constexpr uint32_t RX_TIMEOUT_MAX_MS = (static_cast<uint64_t>(RX_TIMEOUT_MAX_TICKS) * 1000) / RX_TIMEOUT_RTC_HZ;
constexpr uint32_t RX_TIMEOUT_MIN_MS = 100;
constexpr int64_t RX_TIMEOUT_MS = MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS;
static_assert(RX_TIMEOUT_MS > 0, "Diagnostic RX timeout must be positive");
static_assert(RX_TIMEOUT_MS >= RX_TIMEOUT_MIN_MS, "Diagnostic RX timeout must leave margin for a full FLRC frame");
static_assert(RX_TIMEOUT_MS <= RX_TIMEOUT_MAX_MS, "Diagnostic RX timeout exceeds the finite LR2021 24-bit limit");
constexpr uint64_t RX_TIMEOUT_TICKS_WIDE = (static_cast<uint64_t>(RX_TIMEOUT_MS) * RX_TIMEOUT_RTC_HZ + 999) / 1000;
static_assert(RX_TIMEOUT_TICKS_WIDE > 0 && RX_TIMEOUT_TICKS_WIDE <= RX_TIMEOUT_MAX_TICKS,
              "Diagnostic RX timeout does not fit a finite LR2021 24-bit timeout");
constexpr uint32_t RX_TIMEOUT_TICKS = static_cast<uint32_t>(RX_TIMEOUT_TICKS_WIDE);
#endif
#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
#if !(MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)) || !defined(MESHTASTIC_W12_BENCHMARK_RX_TIMEOUT_MS)
#error "Diagnostic RX FIFO clear requires the finite-RX benchmark"
#endif
#endif
#if MESHTASTIC_W12_BENCHMARK && defined(MESHTASTIC_W12_BENCHMARK_BUSY_DBM)
constexpr int16_t BUSY_THRESHOLD_DBM = MESHTASTIC_W12_BENCHMARK_BUSY_DBM;
static_assert(BUSY_THRESHOLD_DBM >= -110 && BUSY_THRESHOLD_DBM <= -60, "Diagnostic CCA threshold out of range");
#else
constexpr int16_t BUSY_THRESHOLD_DBM = -90;
#endif
constexpr uint32_t OBSERVATION_US = 200;
#if RADIOLIB_EXCLUDE_LR2021 != 1
constexpr uint32_t ERROR_IRQS = RADIOLIB_LR2021_IRQ_CRC_ERROR | RADIOLIB_LR2021_IRQ_LEN_ERROR |
                                RADIOLIB_LR2021_IRQ_LORA_HDR_CRC_ERROR | RADIOLIB_LR2021_IRQ_TIMEOUT | RADIOLIB_LR2021_IRQ_ERROR |
                                RADIOLIB_LR2021_IRQ_CMD_ERROR;
constexpr uint32_t RECEIVE_IRQS = RADIOLIB_LR2021_IRQ_RX_DONE | ERROR_IRQS;

inline bool acceptsIrq(uint32_t flags)
{
    return (flags & RADIOLIB_LR2021_IRQ_RX_DONE) && !(flags & ERROR_IRQS);
}

#endif

// Round upward from the pinned driver's CR3/4, CRC4 model; this is an estimate, not measured RF airtime.
inline uint32_t airtimeUs(uint32_t frameBytes)
{
    const uint32_t codedBits = ((frameBytes * 8 + 44) * 4 + 1) / 3;
    return ((101 + codedBits) * 100 + 103) / 104;
}

inline uint32_t durationMs(uint32_t frameBytes)
{
    return (airtimeUs(frameBytes) + COMPLETION_ALLOWANCE_US + 999) / 1000;
}

#if RADIOLIB_EXCLUDE_LR2021 != 1
inline int16_t begin(LR2021 &radio)
{
    int16_t result = radio.beginFLRC(FREQUENCY_MHZ, BIT_RATE_KBPS, RADIOLIB_LR2021_FLRC_CR_3_4, CHIP_POWER_DBM, PREAMBLE_BITS,
                                     RADIOLIB_SHAPING_0_5, 0.0f);
    uint8_t sync[] = {0x2D, 0x01, 0x4B, 0x1D};
    if (result == RADIOLIB_ERR_NONE)
        result = radio.setSyncWord(sync, sizeof(sync));
    if (result == RADIOLIB_ERR_NONE)
        result = radio.setCRC(CRC_BYTES);
    if (result == RADIOLIB_ERR_NONE)
        result = radio.setOutputPower(CHIP_POWER_DBM, 48);
    if (result == RADIOLIB_ERR_NONE)
        result = radio.variablePacketLengthMode(255);
    if (result == RADIOLIB_ERR_NONE) {
        radio.setRfSwitchTable(W12RfSwitch::DIO_PINS, W12RfSwitch::MODE_TABLE);
    }
    return result;
}

// RadioLib's getRSSI() uses zero for both a real reading and a failed command. Keep status separate.
inline int16_t readStatus(Module &module, uint16_t command, uint8_t *data, size_t length)
{
    int16_t result = module.SPIwriteStream(command, nullptr, 0, true, false);
    if (result != RADIOLIB_ERR_NONE)
        return result;
    auto width = module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_CMD];
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_CMD] = Module::BITS_0;
    result = module.SPIreadStream(RADIOLIB_LR2021_CMD_NOP, data, length, true, false);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_CMD] = width;
    return result;
}

// The pinned common IRQ getter discards SPI errors. Validate its raw status-plus-IRQ response. The
// optional status output only exposes bytes already returned by this transaction.
inline int16_t readIrqFlags(Module &module, uint32_t &flags, uint16_t *rawStatus = nullptr)
{
    flags = 0;
    if (rawStatus)
        *rawStatus = 0;
    uint8_t data[6] = {};
    const auto width = module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS];
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_0;
    int16_t result = module.SPItransferStream(nullptr, 0, false, nullptr, data, sizeof(data), true);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = width;
    if (result == RADIOLIB_ERR_NONE && module.spiConfig.parseStatusCb)
        result = module.spiConfig.parseStatusCb(data[0]);
    if (result == RADIOLIB_ERR_NONE) {
        flags = (uint32_t(data[2]) << 24) | (uint32_t(data[3]) << 16) | (uint32_t(data[4]) << 8) | data[5];
        if (rawStatus)
            *rawStatus = (uint16_t(data[0]) << 8) | data[1];
    }
    return result;
}

// These LR2021 FIFO helpers are protected by RadioLib unless GODMODE is enabled. Keep the
// diagnostic access bounded to the existing command/status stream helper and expose no driver API.
#if defined(MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR) && MESHTASTIC_W12_BENCHMARK_RX_FIFO_CLEAR
// Match the pinned driver's protected clearRxFifo command, including its command-status check.
inline int16_t clearRxFifo(Module &module)
{
    return module.SPIwriteStream(RADIOLIB_LR2021_CMD_CLEAR_RX_FIFO, nullptr, 0, true, true);
}
#endif

inline int16_t readFifoIrqFlags(Module &module, uint8_t &rxFlags, uint8_t &txFlags)
{
    uint8_t data[2] = {};
    int16_t result = readStatus(module, RADIOLIB_LR2021_CMD_GET_FIFO_IRQ_FLAGS, data, sizeof(data));
    rxFlags = data[0];
    txFlags = data[1];
    return result;
}

inline int16_t readRxFifoLevel(Module &module, uint16_t &level)
{
    uint8_t data[2] = {};
    int16_t result = readStatus(module, RADIOLIB_LR2021_CMD_GET_RX_FIFO_LEVEL, data, sizeof(data));
    level = (uint16_t(data[0]) << 8) | data[1];
    return result;
}

inline int16_t readRssi(Module &module, bool packet, float &rssi)
{
    uint8_t data[5] = {};
    int16_t result = readStatus(module, packet ? RADIOLIB_LR2021_CMD_GET_FLRC_PACKET_STATUS : RADIOLIB_LR2021_CMD_GET_RSSI_INST,
                                data, packet ? 5 : 2);
    if (result == RADIOLIB_ERR_NONE) {
        uint16_t raw =
            packet ? ((uint16_t(data[2]) << 1) | ((data[4] >> 2) & 1)) : ((uint16_t(data[0]) << 1) | ((data[1] >> 7) & 1));
        rssi = float(raw) / -2.0f;
    }
    return result;
}
#endif
} // namespace W12FlrcProfile
