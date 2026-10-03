#pragma once

#include "meshtastic/admin.pb.h"

namespace RadioMode
{
using Mode = meshtastic_Config_LoRaConfig_RadioMode;

Mode configuredMode(const meshtastic_Config_LoRaConfig &lora);
bool validateUpdate(const meshtastic_Config_LoRaConfig &incoming, const meshtastic_Config_LoRaConfig &current,
                    meshtastic_Config_LoRaConfig &merged);
void initialize(const meshtastic_Config_LoRaConfig &lora);
// Refresh only after LoRa parameters were applied; pending mode selection remains pending.
void refreshActiveLoraConfig(const meshtastic_Config_LoRaConfig &lora);
void markInitialized(bool success);
const meshtastic_Config_LoRaConfig &activeConfig();
bool isFlrc();
bool canTransmit();
meshtastic_RadioModeStatus status(const meshtastic_Config_LoRaConfig &lora);
} // namespace RadioMode
