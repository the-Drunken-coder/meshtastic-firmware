#pragma once

#include "configuration.h"

#if defined(ARCH_ESP32) && !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH

#include "pki_ccm_batch.h"

#include <mbedtls/aes.h>

namespace pki_ccm_batch_esp32
{

class PublicMbedtlsAesBackend final : public pki_ccm_batch::AesBackend
{
  public:
    PublicMbedtlsAesBackend();
    ~PublicMbedtlsAesBackend() override;

    PublicMbedtlsAesBackend(const PublicMbedtlsAesBackend &) = delete;
    PublicMbedtlsAesBackend &operator=(const PublicMbedtlsAesBackend &) = delete;

    bool setKey(const std::uint8_t *key, std::size_t keyLen) override;
    bool cbcEncrypt(const std::uint8_t iv[pki_ccm_batch::kBlockBytes], const std::uint8_t *input, std::size_t length,
                    std::uint8_t *output) override;
    bool ctrXor(const std::uint8_t counter[pki_ccm_batch::kBlockBytes], const std::uint8_t *input, std::size_t length,
                std::uint8_t *output) override;
    bool ecbEncrypt(const std::uint8_t input[pki_ccm_batch::kBlockBytes],
                    std::uint8_t output[pki_ccm_batch::kBlockBytes]) override;
    void clear() override;

  private:
    mbedtls_aes_context aes_{};
};

} // namespace pki_ccm_batch_esp32

#endif
