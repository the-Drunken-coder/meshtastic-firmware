#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH

#include "pki_ccm_batch.h"

class CryptoEngine;

namespace pki_ccm_batch_esp32
{

/** Run fixed-key validation on the selected public mbedTLS backend. */
bool runSelfTest(pki_ccm_batch::AesBackend &backend);

/** Run the same fixed-key checks through the actual selected virtual primitive. */
bool runPrimitiveSelfTest(CryptoEngine &primitive);

} // namespace pki_ccm_batch_esp32

#endif
