#include "configuration.h"

#if defined(ARCH_ESP32) && !(MESHTASTIC_EXCLUDE_PKI) && defined(MESHTASTIC_ESP32_PKI_CCM_BATCH) && MESHTASTIC_ESP32_PKI_CCM_BATCH
#include "pki_ccm_batch_esp32_selftest.h"

#include "CryptoEngine.h"
#include "aes-ccm.h"

#include <esp_heap_caps.h>
#include <esp_psram.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace pki_ccm_batch_esp32
{
namespace
{

using pki_ccm_batch::AesBackend;
using pki_ccm_batch::Result;

constexpr std::size_t kKatLength = 32;
constexpr std::size_t kLayoutBytes = 128;
constexpr std::size_t kProductionWireBytes = pki_ccm_batch::kProductionMaxPlaintext + pki_ccm_batch::kWireOverhead;
// Independent vector generated offline with
// cryptography.hazmat.primitives.ciphers.aead.AESCCM(key, tag_length=8).encrypt(
// nonce, bytes(range(32)), None). The output is split into 32-byte ciphertext
// and eight-byte tag; it is not produced by aes-ccm.cpp or pki_ccm_batch.cpp.
const std::array<std::uint8_t, pki_ccm_batch::kKeyBytes> kKatKey = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
const std::array<std::uint8_t, pki_ccm_batch::kNonceBytes> kKatNonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
const std::array<std::uint8_t, kKatLength> kKatCiphertext = {
    0xe5, 0x17, 0xfc, 0xf6, 0x66, 0x12, 0x4f, 0x2e, 0xb1, 0xec, 0x69, 0xaf, 0x26, 0x94, 0xa8, 0x6a,
    0x2c, 0xaf, 0x3e, 0x8c, 0x09, 0x90, 0x28, 0x4e, 0xc6, 0x1b, 0x5d, 0x80, 0x70, 0xf2, 0x68, 0x45,
};
const std::array<std::uint8_t, pki_ccm_batch::kTagBytes> kKatTag = {0xc9, 0x53, 0xbc, 0x47, 0xdc, 0xd0, 0xe4, 0xd8};

void secureZero(void *memory, std::size_t length)
{
    volatile std::uint8_t *bytes = static_cast<volatile std::uint8_t *>(memory);
    while (length--)
        *bytes++ = 0;
}

bool allZero(const std::uint8_t *bytes, std::size_t length)
{
    for (std::size_t i = 0; i < length; ++i) {
        if (bytes[i] != 0)
            return false;
    }
    return true;
}

class ScopedGenericCrypto
{
  public:
    ScopedGenericCrypto() : previous_(crypto)
    {
        // aes-ccm.cpp uses the global pointer; this local base engine keeps
        // the generic oracle away from the selected ESP backend.
        crypto = &isolated_;
    }

    ~ScopedGenericCrypto() { crypto = previous_; }

    ScopedGenericCrypto(const ScopedGenericCrypto &) = delete;
    ScopedGenericCrypto &operator=(const ScopedGenericCrypto &) = delete;

  private:
    CryptoEngine *previous_;
    CryptoEngine isolated_;
};

bool genericEncrypt(const std::uint8_t *key, const std::uint8_t *nonce, std::size_t length, const std::uint8_t *plaintext,
                    std::uint8_t *ciphertext, std::uint8_t *tag)
{
    ScopedGenericCrypto oracle;
    return aes_ccm_ae(key, pki_ccm_batch::kKeyBytes, nonce, pki_ccm_batch::kTagBytes, plaintext, length, nullptr, 0, ciphertext,
                      tag) == 0;
}

bool genericDecrypt(const std::uint8_t *key, const std::uint8_t *nonce, std::size_t length, const std::uint8_t *ciphertext,
                    const std::uint8_t *tag, std::uint8_t *plaintext)
{
    ScopedGenericCrypto oracle;
    return aes_ccm_ad(key, pki_ccm_batch::kKeyBytes, nonce, pki_ccm_batch::kTagBytes, ciphertext, length, nullptr, 0, tag,
                      plaintext);
}

bool compareGenericBoundaries(AesBackend &backend)
{
    const std::array<std::size_t, 9> lengths = {0, 1, 15, 16, 17, 31, 32, 227, 239};
    for (const std::size_t length : lengths) {
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> plaintext = {0};
        for (std::size_t i = 0; i < length; ++i)
            plaintext[i] = static_cast<std::uint8_t>(i * 29 + 7);
        std::uint8_t zeroByte = 0;
        const std::uint8_t *plaintextPointer = length ? plaintext.data() : &zeroByte;
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> batchCiphertext = {0};
        std::array<std::uint8_t, pki_ccm_batch::kTagBytes> batchTag = {0};
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> genericCiphertext = {0};
        std::array<std::uint8_t, pki_ccm_batch::kTagBytes> genericTag = {0};

        if (pki_ccm_batch::encrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), length,
                                   plaintextPointer, batchCiphertext.data(), batchCiphertext.size(), batchTag.data(),
                                   batchTag.size(), batchTag.size()) != Result::Ok ||
            !genericEncrypt(kKatKey.data(), kKatNonce.data(), length, plaintextPointer, genericCiphertext.data(),
                            genericTag.data()) ||
            std::memcmp(batchCiphertext.data(), genericCiphertext.data(), length) != 0 ||
            std::memcmp(batchTag.data(), genericTag.data(), batchTag.size()) != 0)
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> genericRecovered = {0};
        if (!genericDecrypt(kKatKey.data(), kKatNonce.data(), length, genericCiphertext.data(), genericTag.data(),
                            genericRecovered.data()) ||
            (length != 0 && std::memcmp(genericRecovered.data(), plaintext.data(), length) != 0))
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> recovered = {0};
        if (pki_ccm_batch::decrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), length,
                                   batchCiphertext.data(), batchTag.data(), batchTag.size(), recovered.data(),
                                   recovered.size()) != Result::Ok ||
            (length != 0 && std::memcmp(recovered.data(), plaintext.data(), length) != 0))
            return false;
    }
    return true;
}

bool checkKat(AesBackend &backend)
{
    std::array<std::uint8_t, kKatLength> plaintext = {0};
    for (std::size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<std::uint8_t>(i);
    std::array<std::uint8_t, kKatLength> ciphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
    if (pki_ccm_batch::encrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), plaintext.size(),
                               plaintext.data(), ciphertext.data(), ciphertext.size(), tag.data(), tag.size(),
                               tag.size()) != Result::Ok)
        return false;
    if (ciphertext != kKatCiphertext || tag != kKatTag)
        return false;

    std::array<std::uint8_t, kKatLength> recovered = {0};
    return pki_ccm_batch::decrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), ciphertext.size(),
                                  ciphertext.data(), tag.data(), tag.size(), recovered.data(), recovered.size()) == Result::Ok &&
           recovered == plaintext;
}

bool checkTamperAndWipe(AesBackend &backend)
{
    std::array<std::uint8_t, kKatLength> plaintext = {0};
    for (std::size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<std::uint8_t>(i);
    std::array<std::uint8_t, kKatLength> ciphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
    if (pki_ccm_batch::encrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), plaintext.size(),
                               plaintext.data(), ciphertext.data(), ciphertext.size(), tag.data(), tag.size(),
                               tag.size()) != Result::Ok)
        return false;

    const auto checkReject = [&backend](const std::array<std::uint8_t, pki_ccm_batch::kKeyBytes> &key,
                                        const std::array<std::uint8_t, pki_ccm_batch::kNonceBytes> &nonce,
                                        const std::array<std::uint8_t, kKatLength> &crypt,
                                        const std::array<std::uint8_t, pki_ccm_batch::kTagBytes> &auth) {
        std::array<std::uint8_t, kKatLength + 16> output = {0};
        output.fill(0xa5);
        const Result result = pki_ccm_batch::decrypt(backend, key.data(), key.size(), nonce.data(), nonce.size(), crypt.size(),
                                                     crypt.data(), auth.data(), auth.size(), output.data(), output.size());
        return result == Result::AuthenticationFailed && allZero(output.data(), output.size());
    };

    auto badCiphertext = ciphertext;
    badCiphertext[0] ^= 0x80;
    if (!checkReject(kKatKey, kKatNonce, badCiphertext, tag))
        return false;
    auto badTag = tag;
    badTag[0] ^= 0x01;
    if (!checkReject(kKatKey, kKatNonce, ciphertext, badTag))
        return false;
    auto badNonce = kKatNonce;
    badNonce[0] ^= 0x01;
    if (!checkReject(kKatKey, badNonce, ciphertext, tag))
        return false;
    auto badKey = kKatKey;
    badKey[0] ^= 0x01;
    return checkReject(badKey, kKatNonce, ciphertext, tag);
}

bool checkErrors(AesBackend &backend)
{
    std::array<std::uint8_t, kKatLength> plaintext = {0};
    std::array<std::uint8_t, kKatLength> ciphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
    if (!backend.setKey(kKatKey.data(), kKatKey.size()) || backend.setKey(kKatKey.data(), kKatKey.size() - 1))
        return false;
    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t clearedInput[pki_ccm_batch::kBlockBytes] = {0};
    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t clearedOutput[pki_ccm_batch::kBlockBytes] = {0};
    if (backend.ecbEncrypt(clearedInput, clearedOutput))
        return false;
    if (backend.setKey(nullptr, pki_ccm_batch::kKeyBytes) || backend.setKey(kKatKey.data(), pki_ccm_batch::kKeyBytes - 1) ||
        pki_ccm_batch::encrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(),
                               pki_ccm_batch::kBackendMaxPlaintext + 1, plaintext.data(), ciphertext.data(), ciphertext.size(),
                               tag.data(), tag.size(), tag.size()) != Result::InvalidArgument ||
        pki_ccm_batch::encrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), plaintext.size(),
                               plaintext.data(), ciphertext.data(), plaintext.size() - 1, tag.data(), tag.size(),
                               tag.size()) != Result::InsufficientCapacity ||
        pki_ccm_batch::decrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), ciphertext.size(),
                               ciphertext.data(), tag.data(), tag.size(), plaintext.data(),
                               plaintext.size() - 1) != Result::InsufficientCapacity)
        return false;

    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t block[pki_ccm_batch::kBlockBytes] = {0};
    return !backend.cbcEncrypt(block, block, pki_ccm_batch::kBlockBytes - 1, block) && !backend.ctrXor(block, block, 0, block) &&
           !backend.ecbEncrypt(nullptr, block);
}

bool checkProductionPacketLayout(AesBackend &backend)
{
    std::array<std::uint8_t, pki_ccm_batch::kProductionMaxPlaintext> plaintext = {0};
    for (std::size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<std::uint8_t>(i * 13 + 3);
    std::array<std::uint8_t, kProductionWireBytes> wire = {0};
    std::fill(wire.begin() + pki_ccm_batch::kProductionMaxPlaintext, wire.end(), 0x3c);
    if (pki_ccm_batch::encryptProduction(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(),
                                         plaintext.size(), plaintext.data(), wire.data(), plaintext.size(),
                                         wire.data() + plaintext.size(), pki_ccm_batch::kTagBytes,
                                         pki_ccm_batch::kTagBytes) != Result::Ok)
        return false;

    std::array<std::uint8_t, pki_ccm_batch::kProductionMaxPlaintext> recovered = {0};
    if (pki_ccm_batch::decryptProduction(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), wire.size(),
                                         wire.data(), wire.size(), recovered.data(), recovered.size()) != Result::Ok)
        return false;
    return recovered == plaintext;
}

bool checkLayout(AesBackend &backend, std::uint8_t *arena, std::size_t arenaSize, const char *label, bool unaligned)
{
    if (arena == nullptr || arenaSize < kLayoutBytes || arenaSize > kLayoutBytes + 1 ||
        (unaligned && arenaSize < kLayoutBytes + 1))
        return false;
    // Check every byte around the three logical spans, including DMA bounce-buffer layouts.
    std::memset(arena, 0x7b, arenaSize);
    std::uint8_t *plaintext = arena;
    std::uint8_t *ciphertext = arena + 48;
    std::uint8_t *tag = arena + 96;
    if (unaligned) {
        ++plaintext;
        ++ciphertext;
        ++tag;
    }
    std::array<std::uint8_t, kKatLength> expectedPlaintext = {0};
    for (std::size_t i = 0; i < kKatLength; ++i)
        expectedPlaintext[i] = plaintext[i] = static_cast<std::uint8_t>(i);
    std::memset(ciphertext, 0xa5, kKatLength);
    std::memset(tag, 0x5a, pki_ccm_batch::kTagBytes);
    std::array<std::uint8_t, kLayoutBytes + 1> expectedArena = {0};
    std::memcpy(expectedArena.data(), arena, arenaSize);
    std::memcpy(expectedArena.data() + (ciphertext - arena), kKatCiphertext.data(), kKatLength);
    std::memcpy(expectedArena.data() + (tag - arena), kKatTag.data(), pki_ccm_batch::kTagBytes);
    const Result result =
        pki_ccm_batch::encrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), kKatLength, plaintext,
                               ciphertext, kKatLength, tag, pki_ccm_batch::kTagBytes, pki_ccm_batch::kTagBytes);
    if (result != Result::Ok || std::memcmp(arena, expectedArena.data(), arenaSize) != 0) {
        LOG_ERROR("PKI CCM batch self-test failed (%s)", label);
        return false;
    }
    const Result decryptResult =
        pki_ccm_batch::decrypt(backend, kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), kKatLength,
                               ciphertext, tag, pki_ccm_batch::kTagBytes, plaintext, kKatLength);
    return decryptResult == Result::Ok && std::memcmp(plaintext, expectedPlaintext.data(), kKatLength) == 0 &&
           std::memcmp(arena, expectedArena.data(), arenaSize) == 0;
}

bool checkBufferLayouts(AesBackend &backend)
{
    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t stackArena[kLayoutBytes] = {0};
    if (!checkLayout(backend, stackArena, sizeof(stackArena), "aligned stack", false))
        return false;

    alignas(pki_ccm_batch::kBlockBytes) std::uint8_t unalignedStack[kLayoutBytes + 1] = {0};
    if (!checkLayout(backend, unalignedStack, sizeof(unalignedStack), "unaligned stack", true))
        return false;

    void *internal = heap_caps_aligned_alloc(pki_ccm_batch::kBlockBytes, kLayoutBytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (internal == nullptr)
        return false;
    const bool internalOk =
        checkLayout(backend, static_cast<std::uint8_t *>(internal), kLayoutBytes, "aligned internal heap", false);
    secureZero(internal, kLayoutBytes);
    heap_caps_free(internal);
    if (!internalOk)
        return false;

    void *unalignedInternal =
        heap_caps_aligned_alloc(pki_ccm_batch::kBlockBytes, kLayoutBytes + 1, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (unalignedInternal == nullptr)
        return false;
    const bool unalignedInternalOk =
        checkLayout(backend, static_cast<std::uint8_t *>(unalignedInternal), kLayoutBytes + 1, "unaligned internal heap", true);
    secureZero(unalignedInternal, kLayoutBytes + 1);
    heap_caps_free(unalignedInternal);
    if (!unalignedInternalOk)
        return false;

    if (!esp_psram_is_initialized()) {
        LOG_WARN("PKI CCM batch self-test skipped PSRAM layout: PSRAM unavailable");
        return true;
    }
    void *psram = heap_caps_aligned_alloc(pki_ccm_batch::kBlockBytes, kLayoutBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (psram == nullptr)
        return false;
    const bool psramOk = checkLayout(backend, static_cast<std::uint8_t *>(psram), kLayoutBytes, "aligned PSRAM", false);
    secureZero(psram, kLayoutBytes);
    heap_caps_free(psram);
    if (!psramOk)
        return false;

    void *unalignedPsram =
        heap_caps_aligned_alloc(pki_ccm_batch::kBlockBytes, kLayoutBytes + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (unalignedPsram == nullptr)
        return false;
    const bool unalignedPsramOk =
        checkLayout(backend, static_cast<std::uint8_t *>(unalignedPsram), kLayoutBytes + 1, "unaligned PSRAM", true);
    secureZero(unalignedPsram, kLayoutBytes + 1);
    heap_caps_free(unalignedPsram);
    return unalignedPsramOk;
}

bool checkVirtualPrimitive(CryptoEngine &primitive)
{
    const std::array<std::size_t, 8> lengths = {0, 1, 15, 16, 17, 31, 32, 227};
    for (const std::size_t length : lengths) {
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> plaintext = {0};
        for (std::size_t i = 0; i < length; ++i)
            plaintext[i] = static_cast<std::uint8_t>(i * 17 + 5);
        std::uint8_t zeroByte = 0;
        const std::uint8_t *plaintextPointer = length ? plaintext.data() : &zeroByte;
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> expectedCiphertext = {0};
        std::array<std::uint8_t, pki_ccm_batch::kTagBytes> expectedTag = {0};
        if (!genericEncrypt(kKatKey.data(), kKatNonce.data(), length, plaintextPointer, expectedCiphertext.data(),
                            expectedTag.data()))
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> ciphertext = {0};
        std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
        if (!primitive.encryptPkiCcm(kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), length, plaintextPointer,
                                     ciphertext.data(), length, tag.data(), tag.size(), tag.size(), ciphertext.size(), true) ||
            std::memcmp(ciphertext.data(), expectedCiphertext.data(), length) != 0 || tag != expectedTag)
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> expectedPlaintext = {0};
        if (!genericDecrypt(kKatKey.data(), kKatNonce.data(), length, expectedCiphertext.data(), expectedTag.data(),
                            expectedPlaintext.data()))
            return false;
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> recovered = {0};
        if (!primitive.decryptPkiCcm(kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), length,
                                     ciphertext.data(), tag.data(), tag.size(), recovered.data(), recovered.size(), true) ||
            std::memcmp(recovered.data(), expectedPlaintext.data(), length) != 0)
            return false;
    }

    std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> rejectedPlaintext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> rejectedCiphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> rejectedTag = {0};
    if (primitive.encryptPkiCcm(kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(),
                                pki_ccm_batch::kProductionMaxPlaintext + 1, rejectedPlaintext.data(), rejectedCiphertext.data(),
                                rejectedCiphertext.size(), rejectedTag.data(), rejectedTag.size(), rejectedTag.size(),
                                rejectedCiphertext.size(), true) ||
        primitive.decryptPkiCcm(kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(),
                                pki_ccm_batch::kProductionMaxPlaintext + 1, rejectedCiphertext.data(), rejectedTag.data(),
                                rejectedTag.size(), rejectedPlaintext.data(), rejectedPlaintext.size(), true))
        return false;

    std::array<std::uint8_t, kKatLength> plaintext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> ciphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
    for (std::size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<std::uint8_t>(i);
    if (!primitive.encryptPkiCcm(kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), plaintext.size(),
                                 plaintext.data(), ciphertext.data(), plaintext.size(), tag.data(), tag.size(), tag.size(),
                                 ciphertext.size(), true))
        return false;
    tag[0] ^= 1;
    std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> wipedPlaintext;
    wipedPlaintext.fill(0xa5);
    if (primitive.decryptPkiCcm(kKatKey.data(), kKatKey.size(), kKatNonce.data(), kKatNonce.size(), plaintext.size(),
                                ciphertext.data(), tag.data(), tag.size(), wipedPlaintext.data(), wipedPlaintext.size(), true) ||
        !allZero(wipedPlaintext.data(), wipedPlaintext.size()))
        return false;
    return true;
}

} // namespace

bool runSelfTest(pki_ccm_batch::AesBackend &backend)
{
    return checkErrors(backend) && checkKat(backend) && compareGenericBoundaries(backend) && checkTamperAndWipe(backend) &&
           checkBufferLayouts(backend) && checkProductionPacketLayout(backend);
}

bool runPrimitiveSelfTest(CryptoEngine &primitive)
{
    return checkVirtualPrimitive(primitive);
}

} // namespace pki_ccm_batch_esp32

#endif
