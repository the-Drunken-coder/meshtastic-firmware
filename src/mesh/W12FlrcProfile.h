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
constexpr uint32_t SLOT_MS = 10;
constexpr uint32_t TURNAROUND_MS = 2;
constexpr uint32_t COMPLETION_ALLOWANCE_US = 3000;
constexpr uint32_t TX_TIMEOUT_MS = 100;
constexpr int16_t BUSY_THRESHOLD_DBM = -90;
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

// The pinned common IRQ getter discards SPI errors. Validate its raw status-plus-IRQ response.
inline int16_t readIrqFlags(Module &module, uint32_t &flags)
{
    flags = 0;
    uint8_t data[6] = {};
    const auto width = module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS];
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_0;
    int16_t result = module.SPItransferStream(nullptr, 0, false, nullptr, data, sizeof(data), true);
    module.spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = width;
    if (result == RADIOLIB_ERR_NONE && module.spiConfig.parseStatusCb)
        result = module.spiConfig.parseStatusCb(data[0]);
    if (result == RADIOLIB_ERR_NONE)
        flags = (uint32_t(data[2]) << 24) | (uint32_t(data[3]) << 16) | (uint32_t(data[4]) << 8) | data[5];
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
