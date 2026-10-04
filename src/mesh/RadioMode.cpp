#include "RadioMode.h"
#include "MeshRadio.h"
#include "NodeDB.h"
#include "RadioInterface.h"
#include "Router.h"
#include "configuration.h"

namespace RadioMode
{
namespace
{
meshtastic_Config_LoRaConfig bootConfig = meshtastic_Config_LoRaConfig_init_zero;
bool bootSnapshotTaken = false;
bool initialized = false;

constexpr bool flrcSupported()
{
#ifdef MESHNOLOGY_W12
    return true;
#else
    return false;
#endif
}

constexpr bool experimentalTxEnabled()
{
#if defined(MESHNOLOGY_W12) && defined(MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX) && MESHTASTIC_W12_FLRC_EXPERIMENTAL_TX
    return true;
#else
    return false;
#endif
}

bool selectionValid(const meshtastic_Config_LoRaConfig &lora)
{
    switch (configuredMode(lora)) {
    case meshtastic_Config_LoRaConfig_RadioMode_LORA:
        return true;
    case meshtastic_Config_LoRaConfig_RadioMode_FLRC:
        return flrcSupported() && lora.region == meshtastic_Config_LoRaConfig_RegionCode_US && !lora.serial_hal_only;
    default:
        return false;
    }
}

bool retainedLoraValid(const meshtastic_Config_LoRaConfig &lora)
{
    return RadioInterface::checkConfigRegion(lora) && RadioInterface::validateConfigLora(lora) &&
           (lora.use_preset ||
            (lora.spread_factor == clampSpreadFactor(lora.spread_factor) &&
             lora.coding_rate == clampCodingRate(lora.coding_rate) && lora.bandwidth == clampBandwidthCode(lora.bandwidth)));
}

bool sameRetainedTuning(const meshtastic_Config_LoRaConfig &a, const meshtastic_Config_LoRaConfig &b)
{
    return a.region == b.region && a.use_preset == b.use_preset && a.modem_preset == b.modem_preset &&
           a.bandwidth == b.bandwidth && a.spread_factor == b.spread_factor && a.coding_rate == b.coding_rate &&
           a.frequency_offset == b.frequency_offset && a.override_frequency == b.override_frequency &&
           a.channel_num == b.channel_num && a.tx_power == b.tx_power && a.serial_hal_only == b.serial_hal_only &&
           a.pa_fan_disabled == b.pa_fan_disabled && a.fem_lna_mode == b.fem_lna_mode &&
           a.sx126x_rx_boosted_gain == b.sx126x_rx_boosted_gain;
}

meshtastic_RadioModeStatus_BlockedReason blockedReason(const meshtastic_Config_LoRaConfig &saved)
{
    if (!selectionValid(activeConfig()) || !selectionValid(saved))
        return meshtastic_RadioModeStatus_BlockedReason_INVALID_CONFIGURATION;
    if (isFlrc() && bootSnapshotTaken && !initialized)
        return meshtastic_RadioModeStatus_BlockedReason_NOT_INITIALIZED;
    if (!saved.tx_enabled)
        return meshtastic_RadioModeStatus_BlockedReason_TX_DISABLED;
    if (isFlrc() && !experimentalTxEnabled())
        return meshtastic_RadioModeStatus_BlockedReason_RF_APPROVAL_REQUIRED;
    return meshtastic_RadioModeStatus_BlockedReason_NONE;
}
} // namespace

Mode configuredMode(const meshtastic_Config_LoRaConfig &lora)
{
    return lora.has_radio_mode ? lora.radio_mode : meshtastic_Config_LoRaConfig_RadioMode_LORA;
}

bool validateUpdate(const meshtastic_Config_LoRaConfig &incoming, const meshtastic_Config_LoRaConfig &current,
                    meshtastic_Config_LoRaConfig &merged)
{
    auto candidate = incoming;
    if (!incoming.has_radio_mode) {
        candidate.has_radio_mode = current.has_radio_mode;
        candidate.radio_mode = current.radio_mode;
    }
    if (!selectionValid(candidate))
        return false;
    const bool tuneIsRetained = configuredMode(candidate) != configuredMode(current) || isFlrc() ||
                                configuredMode(candidate) == meshtastic_Config_LoRaConfig_RadioMode_FLRC ||
                                configuredMode(current) != configuredMode(activeConfig());
    if (tuneIsRetained && !sameRetainedTuning(candidate, current)) {
        // Invalid saved settings need a complete valid LoRa correction, not an impossible mode-only escape.
        const bool correctiveLora = configuredMode(candidate) == meshtastic_Config_LoRaConfig_RadioMode_LORA &&
                                    (!selectionValid(current) || !retainedLoraValid(current)) && retainedLoraValid(candidate);
        if (!correctiveLora)
            return false;
    }
    merged = candidate;
    return true;
}

void initialize(const meshtastic_Config_LoRaConfig &lora)
{
    bootConfig = lora;
    bootSnapshotTaken = true;
    initialized = false;
}

void refreshActiveLoraConfig(const meshtastic_Config_LoRaConfig &lora)
{
    if (configuredMode(activeConfig()) != meshtastic_Config_LoRaConfig_RadioMode_LORA)
        return;
    bootConfig = lora;
    // A live LoRa tuning update cannot activate a modulation selection waiting for reboot.
    bootConfig.has_radio_mode = true;
    bootConfig.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_LORA;
    bootSnapshotTaken = true;
}

void markInitialized(bool success)
{
    initialized = success;
}

const meshtastic_Config_LoRaConfig &activeConfig()
{
    return bootSnapshotTaken ? bootConfig : config.lora;
}

bool isFlrc()
{
    return configuredMode(activeConfig()) == meshtastic_Config_LoRaConfig_RadioMode_FLRC;
}

bool canTransmit()
{
    return blockedReason(config.lora) == meshtastic_RadioModeStatus_BlockedReason_NONE;
}

meshtastic_RadioModeStatus status(const meshtastic_Config_LoRaConfig &lora)
{
    meshtastic_RadioModeStatus result = meshtastic_RadioModeStatus_init_zero;
    result.capability_version = 1;
    result.flrc_supported = flrcSupported();
    result.configured_mode = configuredMode(lora);
    result.active_mode = configuredMode(activeConfig());
    result.active_initialized = initialized;
    result.restart_pending = result.configured_mode != result.active_mode;
    result.configuration_valid = selectionValid(activeConfig());
    result.blocked_reason = blockedReason(lora);
    result.transmit_allowed = result.blocked_reason == meshtastic_RadioModeStatus_BlockedReason_NONE;
    result.experimental_tx_enabled = experimentalTxEnabled();
    if (result.active_initialized && result.configuration_valid && isFlrc())
        result.carrier_mhz = 915.0f;
    else if (result.active_initialized && router && router->getRadioIface())
        result.carrier_mhz = router->getRadioIface()->getFreq();
    return result;
}
} // namespace RadioMode
