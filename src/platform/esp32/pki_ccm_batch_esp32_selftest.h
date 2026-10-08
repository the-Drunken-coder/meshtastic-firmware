#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH

#include "pki_ccm_batch.h"

namespace pki_ccm_batch_esp32
{

/** Narrow seam used to test the actual ESP CryptoEngine override without DH/RNG setup. */
class PkiCcmPrimitive
{
  public:
    virtual ~PkiCcmPrimitive() = default;

    virtual bool encryptPkiCcm(const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
                               std::size_t plainLen, const std::uint8_t *plain, std::uint8_t *crypt, std::size_t cryptCapacity,
                               std::uint8_t *auth, std::size_t authLen, std::size_t authCapacity, std::size_t outputCapacity,
                               bool batchRequested) = 0;
    virtual bool decryptPkiCcm(const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
                               std::size_t cryptLen, const std::uint8_t *crypt, const std::uint8_t *auth, std::size_t authLen,
                               std::uint8_t *plain, std::size_t plainCapacity, bool batchRequested) = 0;
};

/** Run fixed-key validation on the selected public mbedTLS backend. */
bool runSelfTest(pki_ccm_batch::AesBackend &backend);

/** Run the same fixed-key checks through the actual selected virtual primitive. */
bool runPrimitiveSelfTest(PkiCcmPrimitive &primitive);

} // namespace pki_ccm_batch_esp32

#endif
