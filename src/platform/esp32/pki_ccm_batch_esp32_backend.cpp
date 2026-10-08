#include "configuration.h"

#if defined(ARCH_ESP32) && !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH
#include "pki_ccm_batch_esp32_backend.h"

#include <cstring>

namespace pki_ccm_batch_esp32
{
namespace
{

void secureZero(void *memory, std::size_t length)
{
    volatile std::uint8_t *bytes = static_cast<volatile std::uint8_t *>(memory);
    while (length--)
        *bytes++ = 0;
}

} // namespace

PublicMbedtlsAesBackend::PublicMbedtlsAesBackend()
{
    mbedtls_aes_init(&aes_);
}

PublicMbedtlsAesBackend::~PublicMbedtlsAesBackend()
{
    mbedtls_aes_free(&aes_);
    secureZero(&aes_, sizeof(aes_));
}

bool PublicMbedtlsAesBackend::setKey(const std::uint8_t *key, std::size_t keyLen)
{
    if (key == nullptr || keyLen != pki_ccm_batch::kKeyBytes) {
        clear();
        return false;
    }

    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t keyCopy[pki_ccm_batch::kKeyBytes];
    std::memcpy(keyCopy, key, sizeof(keyCopy));
    const int result = mbedtls_aes_setkey_enc(&aes_, keyCopy, static_cast<unsigned int>(keyLen * 8));
    secureZero(keyCopy, sizeof(keyCopy));
    if (result != 0) {
        clear();
        return false;
    }
    return true;
}

bool PublicMbedtlsAesBackend::cbcEncrypt(const std::uint8_t iv[pki_ccm_batch::kBlockBytes], const std::uint8_t *input,
                                         std::size_t length, std::uint8_t *output)
{
    if (iv == nullptr || input == nullptr || output == nullptr || length == 0 || length > pki_ccm_batch::kCbcInputScratchBytes ||
        length % pki_ccm_batch::kBlockBytes != 0) {
        clear();
        return false;
    }

    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t ivCopy[pki_ccm_batch::kBlockBytes];
    std::memcpy(ivCopy, iv, sizeof(ivCopy));
    const int result = mbedtls_aes_crypt_cbc(&aes_, MBEDTLS_AES_ENCRYPT, length, ivCopy, input, output);
    secureZero(ivCopy, sizeof(ivCopy));
    if (result != 0)
        clear();
    return result == 0;
}

bool PublicMbedtlsAesBackend::ctrXor(const std::uint8_t counter[pki_ccm_batch::kBlockBytes], const std::uint8_t *input,
                                     std::size_t length, std::uint8_t *output)
{
    // The shared algorithm skips zero-length CTR. Keeping that rule here also
    // avoids target-specific zero-length behavior in the public API.
    if (counter == nullptr || input == nullptr || output == nullptr || length == 0 ||
        length > pki_ccm_batch::kBackendMaxPlaintext) {
        clear();
        return false;
    }

    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t counterCopy[pki_ccm_batch::kBlockBytes];
    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t streamBlock[pki_ccm_batch::kBlockBytes] = {0};
    std::memcpy(counterCopy, counter, sizeof(counterCopy));
    std::size_t offset = 0;
    const int result = mbedtls_aes_crypt_ctr(&aes_, length, &offset, counterCopy, streamBlock, input, output);
    secureZero(counterCopy, sizeof(counterCopy));
    secureZero(streamBlock, sizeof(streamBlock));
    secureZero(&offset, sizeof(offset));
    if (result != 0)
        clear();
    return result == 0;
}

bool PublicMbedtlsAesBackend::ecbEncrypt(const std::uint8_t input[pki_ccm_batch::kBlockBytes],
                                         std::uint8_t output[pki_ccm_batch::kBlockBytes])
{
    if (input == nullptr || output == nullptr) {
        clear();
        return false;
    }
    const int result = mbedtls_aes_crypt_ecb(&aes_, MBEDTLS_AES_ENCRYPT, input, output);
    if (result != 0)
        clear();
    return result == 0;
}

void PublicMbedtlsAesBackend::clear()
{
    // free() clears the schedule; init() makes the object safe for the next
    // public batch call even when clear() is the entry cleanup.
    mbedtls_aes_free(&aes_);
    secureZero(&aes_, sizeof(aes_));
    mbedtls_aes_init(&aes_);
}

} // namespace pki_ccm_batch_esp32

#endif
