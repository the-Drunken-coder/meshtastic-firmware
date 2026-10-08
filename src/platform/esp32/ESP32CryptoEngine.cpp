#include "CryptoEngine.h"
#include "configuration.h"

#include "mbedtls/aes.h"
#if !(MESHTASTIC_EXCLUDE_PKI)
#include "pki_ccm_batch.h"
#include "pki_ccm_batch_esp32_backend.h"
#include "pki_ccm_batch_esp32_selftest.h"
#endif
#if !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH
#include <esp_heap_caps.h>
#include <freertos/task.h>
#endif

#if !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH
class ESP32CryptoEngine : public CryptoEngine, public pki_ccm_batch_esp32::PkiCcmPrimitive
#else
class ESP32CryptoEngine : public CryptoEngine
#endif
{

    mbedtls_aes_context aes;
#if !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH
    pki_ccm_batch_esp32::PublicMbedtlsAesBackend pkiBatchBackend;
    bool pkiBatchActive = false;
#endif

  public:
    ESP32CryptoEngine() { mbedtls_aes_init(&aes); }

    ~ESP32CryptoEngine() { mbedtls_aes_free(&aes); }

#if !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH
    // Selection follows the explicit build opt-in. Readiness is checked by the
    // primitive so an unarmed backend cannot silently select generic CCM.
    bool pkiCcmBatchEnabled() const override { return true; }

    bool encryptPkiCcm(const uint8_t *key, size_t keyLen, const uint8_t *nonce, size_t nonceLen, size_t plainLen,
                       const uint8_t *plain, uint8_t *crypt, size_t cryptCapacity, uint8_t *auth, size_t authLen,
                       size_t authCapacity, size_t outputCapacity, bool batchRequested) override
    {
        if (batchRequested) {
            pki_ccm_batch::Result result;
            if (!pkiBatchActive) {
                pkiBatchBackend.clear();
                result = pki_ccm_batch::Result::BackendError;
            } else if (plainLen > pki_ccm_batch::kProductionMaxPlaintext) {
                pkiBatchBackend.clear();
                result = pki_ccm_batch::Result::InvalidArgument;
            } else if (outputCapacity == 0 || outputCapacity < plainLen + pki_ccm_batch::kWireOverhead || authCapacity == 0 ||
                       (plainLen != 0 && cryptCapacity == 0)) {
                pkiBatchBackend.clear();
                result = pki_ccm_batch::Result::InsufficientCapacity;
            } else {
                result = pki_ccm_batch::encryptProduction(pkiBatchBackend, key, keyLen, nonce, nonceLen, plainLen, plain, crypt,
                                                          cryptCapacity, auth, authLen, authCapacity);
            }
            if (result != pki_ccm_batch::Result::Ok)
                LOG_WARN("PKI CCM batch encrypt failed: %s", pki_ccm_batch::resultName(result));
            return result == pki_ccm_batch::Result::Ok;
        }
        return CryptoEngine::encryptPkiCcm(key, keyLen, nonce, nonceLen, plainLen, plain, crypt, cryptCapacity, auth, authLen,
                                           authCapacity, outputCapacity, batchRequested);
    }

    bool decryptPkiCcm(const uint8_t *key, size_t keyLen, const uint8_t *nonce, size_t nonceLen, size_t cryptLen,
                       const uint8_t *crypt, const uint8_t *auth, size_t authLen, uint8_t *plain, size_t plainCapacity,
                       bool batchRequested) override
    {
        if (batchRequested) {
            pki_ccm_batch::Result result;
            if (!pkiBatchActive) {
                pkiBatchBackend.clear();
                result = pki_ccm_batch::Result::BackendError;
            } else if (plainCapacity == 0) {
                pkiBatchBackend.clear();
                result = pki_ccm_batch::Result::InsufficientCapacity;
            } else if (cryptLen > pki_ccm_batch::kProductionMaxPlaintext) {
                pkiBatchBackend.clear();
                result = pki_ccm_batch::Result::InvalidArgument;
            } else {
                result = pki_ccm_batch::decrypt(pkiBatchBackend, key, keyLen, nonce, nonceLen, cryptLen, crypt, auth, authLen,
                                                plain, plainCapacity);
            }
            if (result != pki_ccm_batch::Result::Ok)
                LOG_WARN("PKI CCM batch decrypt failed: %s", pki_ccm_batch::resultName(result));
            return result == pki_ccm_batch::Result::Ok;
        }
        return CryptoEngine::decryptPkiCcm(key, keyLen, nonce, nonceLen, cryptLen, crypt, auth, authLen, plain, plainCapacity,
                                           batchRequested);
    }

    bool runPkiBatchSelfTest()
    {
        if (!pki_ccm_batch_esp32::runSelfTest(pkiBatchBackend)) {
            pkiBatchActive = false;
            pkiBatchBackend.clear();
            return false;
        }
        pkiBatchActive = true;
        if (!pki_ccm_batch_esp32::runPrimitiveSelfTest(*this)) {
            pkiBatchActive = false;
            pkiBatchBackend.clear();
            return false;
        }
        return true;
    }
#endif

    /**
     * Encrypt a packet
     *
     * @param bytes is updated in place
     *  TODO: return bool, and handle graciously when something fails
     */
    virtual void encryptAESCtr(CryptoKey _key, uint8_t *_nonce, size_t numBytes, uint8_t *bytes) override
    {
        if (_key.length > 0) {
            if (numBytes <= MAX_BLOCKSIZE) {
                mbedtls_aes_setkey_enc(&aes, _key.bytes, _key.length * 8);
                static uint8_t scratch[MAX_BLOCKSIZE];
                uint8_t stream_block[16];
                size_t nc_off = 0;
                memcpy(scratch, bytes, numBytes);
                memset(scratch + numBytes, 0,
                       sizeof(scratch) - numBytes); // Fill rest of buffer with zero (in case cypher looks at it)
                mbedtls_aes_crypt_ctr(&aes, numBytes, &nc_off, _nonce, stream_block, scratch, bytes);
            } else {
                LOG_ERROR("Packet too large for crypto engine: %d. noop encryption", numBytes);
            }
        }
    }
};

CryptoEngine *crypto = new ESP32CryptoEngine();

bool esp32PkiCcmBatchStartupSelfTest()
{
#if !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH
    auto *engine = static_cast<ESP32CryptoEngine *>(crypto);
    const bool passed = engine != nullptr && engine->runPkiBatchSelfTest();
    // Startup-only evidence. No formatting or serial output is added to the measured packet path.
    LOG_INFO("PKI CCM batch self-test %s; stack headroom %u bytes, internal heap free %u bytes", passed ? "passed" : "failed",
             static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)),
             static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)));
    return passed;
#else
    return true;
#endif
}
