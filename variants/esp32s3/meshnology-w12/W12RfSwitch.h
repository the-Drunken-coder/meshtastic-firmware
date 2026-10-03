#pragma once
#include <RadioLib.h>

namespace W12RfSwitch
{

inline constexpr uint32_t DIO_PINS[Module::RFSWITCH_MAX_PINS] = {
    RADIOLIB_LR2021_DIO5, RADIOLIB_LR2021_DIO6, RADIOLIB_LR2021_DIO9, RADIOLIB_LR2021_DIO10, RADIOLIB_LR2021_DIO11,
};
inline constexpr Module::RfSwitchMode_t MODE_TABLE[] = {
    {LR2021::MODE_STBY, {LOW, LOW, LOW, LOW, LOW}},   {LR2021::MODE_RX, {LOW, LOW, LOW, LOW, HIGH}},
    {LR2021::MODE_TX, {LOW, LOW, HIGH, LOW, HIGH}},   {LR2021::MODE_RX_HF, {LOW, HIGH, LOW, LOW, LOW}},
    {LR2021::MODE_TX_HF, {HIGH, LOW, LOW, LOW, LOW}}, END_OF_MODE_TABLE,
};
} // namespace W12RfSwitch
