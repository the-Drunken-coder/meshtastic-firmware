// Firmware-native PKI batch checks compare against the existing CCM functions.

#include "pki_ccm_batch_firmware_test.h"
#include "CryptoEngine.h"
#include "aes-ccm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace pki_ccm_batch_firmware_test
{

namespace
{

bool allZero(const std::uint8_t *bytes, std::size_t length)
{
    for (std::size_t i = 0; i < length; ++i) {
        if (bytes[i] != 0)
            return false;
    }
    return true;
}

#if defined(PIO_UNIT_TESTING)
class NativeSoftwareAesBackend final : public pki_ccm_batch::AesBackend
{
  public:
    bool setKey(const std::uint8_t *key, std::size_t keyLen) override
    {
        clear();
        if (key == nullptr || keyLen != pki_ccm_batch::kKeyBytes)
            return false;
        engine_.aesSetKey(key, keyLen);
        keyed_ = true;
        return true;
    }

    bool cbcEncrypt(const std::uint8_t iv[pki_ccm_batch::kBlockBytes], const std::uint8_t *input, std::size_t length,
                    std::uint8_t *output) override
    {
        if (!keyed_ || iv == nullptr || input == nullptr || output == nullptr || length == 0 ||
            length > pki_ccm_batch::kCbcInputScratchBytes || length % pki_ccm_batch::kBlockBytes != 0)
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBlockBytes> previous;
        std::array<std::uint8_t, pki_ccm_batch::kBlockBytes> block;
        std::memcpy(previous.data(), iv, previous.size());
        for (std::size_t offset = 0; offset < length; offset += pki_ccm_batch::kBlockBytes) {
            for (std::size_t i = 0; i < block.size(); ++i)
                block[i] = input[offset + i] ^ previous[i];
            engine_.aesEncrypt(block.data(), output + offset);
            std::memcpy(previous.data(), output + offset, previous.size());
        }
        secureZero(previous.data(), previous.size());
        secureZero(block.data(), block.size());
        return true;
    }

    bool ctrXor(const std::uint8_t counter[pki_ccm_batch::kBlockBytes], const std::uint8_t *input, std::size_t length,
                std::uint8_t *output) override
    {
        if (!keyed_ || counter == nullptr || input == nullptr || output == nullptr || length == 0 ||
            length > pki_ccm_batch::kBackendMaxPlaintext)
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBlockBytes> counterCopy;
        std::array<std::uint8_t, pki_ccm_batch::kBlockBytes> stream;
        std::memcpy(counterCopy.data(), counter, counterCopy.size());
        std::size_t offset = 0;
        while (offset < length) {
            engine_.aesEncrypt(counterCopy.data(), stream.data());
            const std::size_t blockLength = std::min(stream.size(), length - offset);
            for (std::size_t i = 0; i < blockLength; ++i)
                output[offset + i] = input[offset + i] ^ stream[i];
            offset += blockLength;
            for (std::size_t i = counterCopy.size(); i-- > 0;) {
                if (++counterCopy[i] != 0)
                    break;
            }
        }
        secureZero(counterCopy.data(), counterCopy.size());
        secureZero(stream.data(), stream.size());
        return true;
    }

    bool ecbEncrypt(const std::uint8_t input[pki_ccm_batch::kBlockBytes],
                    std::uint8_t output[pki_ccm_batch::kBlockBytes]) override
    {
        if (!keyed_ || input == nullptr || output == nullptr)
            return false;
        std::array<std::uint8_t, pki_ccm_batch::kBlockBytes> inputCopy;
        std::memcpy(inputCopy.data(), input, inputCopy.size());
        engine_.aesEncrypt(inputCopy.data(), output);
        secureZero(inputCopy.data(), inputCopy.size());
        return true;
    }

    void clear() override
    {
        keyed_ = false;
        engine_.aesSetKey(nullptr, 0);
    }

  private:
    static void secureZero(void *memory, std::size_t length)
    {
        volatile std::uint8_t *bytes = static_cast<volatile std::uint8_t *>(memory);
        while (length--)
            *bytes++ = 0;
    }

    CryptoEngine engine_;
    bool keyed_ = false;
};
#endif

} // namespace

class ScopedGenericCrypto
{
  public:
    ScopedGenericCrypto() : previous_(crypto)
    {
        // aes-ccm.cpp uses the global crypto pointer. The isolated native
        // oracle prevents this test from clobbering the production object.
        crypto = &isolated_;
    }

    ~ScopedGenericCrypto() { crypto = previous_; }

    ScopedGenericCrypto(const ScopedGenericCrypto &) = delete;
    ScopedGenericCrypto &operator=(const ScopedGenericCrypto &) = delete;

  private:
    CryptoEngine *previous_;
    CryptoEngine isolated_;
};

bool firmwareGenericEncrypt(const std::uint8_t *key, const std::uint8_t *nonce, std::size_t length, const std::uint8_t *plaintext,
                            std::uint8_t *ciphertext, std::uint8_t *tag)
{
    ScopedGenericCrypto isolatedOracle;
    return aes_ccm_ae(key, pki_ccm_batch::kKeyBytes, nonce, pki_ccm_batch::kTagBytes, plaintext, length, nullptr, 0, ciphertext,
                      tag) == 0;
}

bool firmwareGenericDecrypt(const std::uint8_t *key, const std::uint8_t *nonce, std::size_t length,
                            const std::uint8_t *ciphertext, const std::uint8_t *tag, std::uint8_t *plaintext)
{
    ScopedGenericCrypto isolatedOracle;
    return aes_ccm_ad(key, pki_ccm_batch::kKeyBytes, nonce, pki_ccm_batch::kTagBytes, ciphertext, length, nullptr, 0, tag,
                      plaintext);
}

bool checkIndependentKat(pki_ccm_batch::AesBackend &batchBackend)
{
    // Generated independently with Python cryptography.hazmat AESCCM(tag_length=8), then split
    // into ciphertext and tag. This is deliberately separate from both firmware CCM paths.
    constexpr std::array<std::uint8_t, pki_ccm_batch::kKeyBytes> key = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    constexpr std::array<std::uint8_t, pki_ccm_batch::kNonceBytes> nonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    constexpr std::array<std::uint8_t, 32> plaintext = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    };
    constexpr std::array<std::uint8_t, 32> expectedCiphertext = {
        0xe5, 0x17, 0xfc, 0xf6, 0x66, 0x12, 0x4f, 0x2e, 0xb1, 0xec, 0x69, 0xaf, 0x26, 0x94, 0xa8, 0x6a,
        0x2c, 0xaf, 0x3e, 0x8c, 0x09, 0x90, 0x28, 0x4e, 0xc6, 0x1b, 0x5d, 0x80, 0x70, 0xf2, 0x68, 0x45,
    };
    constexpr std::array<std::uint8_t, pki_ccm_batch::kTagBytes> expectedTag = {0xc9, 0x53, 0xbc, 0x47, 0xdc, 0xd0, 0xe4, 0xd8};
    std::array<std::uint8_t, plaintext.size()> ciphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
    if (pki_ccm_batch::encrypt(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), plaintext.size(),
                               plaintext.data(), ciphertext.data(), ciphertext.size(), tag.data(), tag.size(),
                               tag.size()) != pki_ccm_batch::Result::Ok ||
        ciphertext != expectedCiphertext || tag != expectedTag)
        return false;

    std::array<std::uint8_t, plaintext.size()> recovered = {0};
    return pki_ccm_batch::decrypt(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), ciphertext.size(),
                                  ciphertext.data(), tag.data(), tag.size(), recovered.data(),
                                  recovered.size()) == pki_ccm_batch::Result::Ok &&
           recovered == plaintext;
}

/**
 * Compare the production-shaped batch function to actual firmware generic CCM.
 * The caller supplies the native AES backend used by the batch function.
 */
bool compareBoundaries(pki_ccm_batch::AesBackend &batchBackend)
{
    const std::array<std::uint8_t, pki_ccm_batch::kKeyBytes> key = {0};
    const std::array<std::uint8_t, pki_ccm_batch::kNonceBytes> nonce = {0};
    const std::array<std::size_t, 9> lengths = {0, 1, 15, 16, 17, 31, 32, 227, 239};
    for (const std::size_t length : lengths) {
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> plaintext = {0};
        for (std::size_t i = 0; i < length; ++i)
            plaintext[i] = static_cast<std::uint8_t>(i * 29 + 7);

        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> batchCiphertext = {0};
        std::array<std::uint8_t, pki_ccm_batch::kTagBytes> batchTag = {0};
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> genericCiphertext = {0};
        std::array<std::uint8_t, pki_ccm_batch::kTagBytes> genericTag = {0};
        std::uint8_t zeroByte = 0;
        const std::uint8_t *plaintextPointer = length ? plaintext.data() : &zeroByte;

        if (pki_ccm_batch::encrypt(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), length, plaintextPointer,
                                   batchCiphertext.data(), batchCiphertext.size(), batchTag.data(), batchTag.size(),
                                   batchTag.size()) != pki_ccm_batch::Result::Ok)
            return false;
        if (!firmwareGenericEncrypt(key.data(), nonce.data(), length, plaintextPointer, genericCiphertext.data(),
                                    genericTag.data()))
            return false;
        if (std::memcmp(batchCiphertext.data(), genericCiphertext.data(), length) != 0 ||
            std::memcmp(batchTag.data(), genericTag.data(), batchTag.size()) != 0)
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> genericPlaintext = {0};
        if (!firmwareGenericDecrypt(key.data(), nonce.data(), length, genericCiphertext.data(), genericTag.data(),
                                    genericPlaintext.data()))
            return false;
        if (length && std::memcmp(genericPlaintext.data(), plaintext.data(), length) != 0)
            return false;

        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> batchPlaintext = {0};
        if (pki_ccm_batch::decrypt(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), length,
                                   batchCiphertext.data(), batchTag.data(), batchTag.size(), batchPlaintext.data(),
                                   batchPlaintext.size()) != pki_ccm_batch::Result::Ok)
            return false;
        if (length && std::memcmp(batchPlaintext.data(), plaintext.data(), length) != 0)
            return false;
    }
    return true;
}

bool checkTamperAndWipe(pki_ccm_batch::AesBackend &batchBackend)
{
    const std::array<std::uint8_t, pki_ccm_batch::kKeyBytes> key = {0};
    const std::array<std::uint8_t, pki_ccm_batch::kNonceBytes> nonce = {0};
    std::array<std::uint8_t, 32> plaintext = {0};
    for (std::size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<std::uint8_t>(i * 7 + 1);
    std::array<std::uint8_t, 32> ciphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
    if (pki_ccm_batch::encrypt(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), plaintext.size(),
                               plaintext.data(), ciphertext.data(), ciphertext.size(), tag.data(), tag.size(),
                               tag.size()) != pki_ccm_batch::Result::Ok)
        return false;

    const auto checkRejected = [&](const std::array<std::uint8_t, 32> &tamperedCiphertext,
                                   const std::array<std::uint8_t, pki_ccm_batch::kTagBytes> &tamperedTag) {
        std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> output;
        output.fill(0xa5);
        const auto result = pki_ccm_batch::decrypt(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(),
                                                   tamperedCiphertext.size(), tamperedCiphertext.data(), tamperedTag.data(),
                                                   tamperedTag.size(), output.data(), output.size());
        return result == pki_ccm_batch::Result::AuthenticationFailed && allZero(output.data(), output.size());
    };

    auto badCiphertext = ciphertext;
    badCiphertext[0] ^= 0x80;
    if (!checkRejected(badCiphertext, tag))
        return false;
    auto badTag = tag;
    badTag[0] ^= 1;
    return checkRejected(ciphertext, badTag);
}

bool checkWireFramingAndCapacity(pki_ccm_batch::AesBackend &batchBackend)
{
    const std::array<std::uint8_t, pki_ccm_batch::kKeyBytes> key = {0};
    std::array<std::uint8_t, pki_ccm_batch::kNonceBytes> nonce = {0x62, 0xd6, 0xb2, 0x13, 0x03, 0x6a, 0x79,
                                                                  0x2b, 0x29, 0x00, 0x00, 0x00, 0x00};
    constexpr std::size_t plaintextLength = 10;
    std::array<std::uint8_t, plaintextLength> plaintext = {0x08, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74, 0x48, 0x00};
    std::array<std::uint8_t, plaintextLength> ciphertext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> tag = {0};
    std::array<std::uint8_t, plaintextLength + pki_ccm_batch::kWireOverhead> wire = {0};
    const std::uint32_t extraNonce = 0x44332211;
    std::memcpy(nonce.data() + 4, &extraNonce, sizeof(extraNonce));
    if (pki_ccm_batch::encrypt(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), plaintext.size(),
                               plaintext.data(), ciphertext.data(), ciphertext.size(), tag.data(), tag.size(),
                               tag.size()) != pki_ccm_batch::Result::Ok)
        return false;
    std::memcpy(wire.data(), ciphertext.data(), ciphertext.size());
    std::memcpy(wire.data() + ciphertext.size(), tag.data(), tag.size());
    std::memcpy(wire.data() + ciphertext.size() + tag.size(), &extraNonce, sizeof(extraNonce));
    const auto wireBefore = wire;
    std::uint32_t parsedExtraNonce = 0;
    std::memcpy(&parsedExtraNonce, wire.data() + plaintext.size() + pki_ccm_batch::kTagBytes, sizeof(parsedExtraNonce));
    if (parsedExtraNonce != extraNonce ||
        std::memcmp(nonce.data() + 4, wire.data() + plaintext.size() + pki_ccm_batch::kTagBytes, sizeof(parsedExtraNonce)) != 0)
        return false;
    std::array<std::uint8_t, pki_ccm_batch::kBackendMaxPlaintext> recovered;
    recovered.fill(0xa5);
    if (pki_ccm_batch::decryptWire(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), wire.size(), wire.data(),
                                   wire.size(), recovered.data(), recovered.size()) != pki_ccm_batch::Result::Ok ||
        std::memcmp(recovered.data(), plaintext.data(), plaintext.size()) != 0 || wire != wireBefore)
        return false;

    recovered.fill(0xa5);
    if (pki_ccm_batch::decryptWire(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), wire.size(), wire.data(),
                                   wire.size() - 1, recovered.data(),
                                   recovered.size()) != pki_ccm_batch::Result::InvalidArgument ||
        !std::all_of(recovered.begin(), recovered.end(), [](std::uint8_t value) { return value == 0xa5; }))
        return false;

    std::array<std::uint8_t, 48> aliasStorage = {0};
    std::memcpy(aliasStorage.data(), wire.data(), wire.size());
    const auto aliasBefore = aliasStorage;
    if (pki_ccm_batch::decryptWire(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), wire.size(),
                                   aliasStorage.data(), 40, aliasStorage.data() + 24,
                                   10) != pki_ccm_batch::Result::InvalidArgument ||
        aliasStorage != aliasBefore)
        return false;

    std::array<std::uint8_t, pki_ccm_batch::kProductionMaxPlaintext> longPlaintext = {0};
    std::array<std::uint8_t, pki_ccm_batch::kProductionMaxPlaintext + pki_ccm_batch::kWireOverhead> longWire = {0};
    for (std::size_t i = 0; i < longPlaintext.size(); ++i)
        longPlaintext[i] = static_cast<std::uint8_t>(i * 3 + 9);
    std::fill(longWire.begin() + pki_ccm_batch::kProductionMaxPlaintext, longWire.end(), 0x3c);
    if (pki_ccm_batch::encryptProduction(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), longPlaintext.size(),
                                         longPlaintext.data(), longWire.data(), longPlaintext.size(),
                                         longWire.data() + longPlaintext.size(), pki_ccm_batch::kTagBytes,
                                         pki_ccm_batch::kTagBytes) != pki_ccm_batch::Result::Ok)
        return false;
    std::array<std::uint8_t, pki_ccm_batch::kProductionMaxPlaintext> longRecovered = {0};
    return pki_ccm_batch::decryptProduction(batchBackend, key.data(), key.size(), nonce.data(), nonce.size(), longWire.size(),
                                            longWire.data(), longWire.size(), longRecovered.data(),
                                            longRecovered.size()) == pki_ccm_batch::Result::Ok &&
           longRecovered == longPlaintext;
}

#if defined(PIO_UNIT_TESTING)
namespace
{

class SelectedPolicyCryptoEngine final : public CryptoEngine
{
  public:
    explicit SelectedPolicyCryptoEngine(bool armed = true) : armed_(armed) {}

    bool pkiCcmBatchEnabled() const override { return true; }

    bool encryptPkiCcm(const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
                       std::size_t plainLen, const std::uint8_t *plain, std::uint8_t *crypt, std::size_t cryptCapacity,
                       std::uint8_t *auth, std::size_t authLen, std::size_t authCapacity, std::size_t outputCapacity,
                       bool batchRequested) override
    {
        if (!batchRequested)
            return CryptoEngine::encryptPkiCcm(key, keyLen, nonce, nonceLen, plainLen, plain, crypt, cryptCapacity, auth, authLen,
                                               authCapacity, outputCapacity, batchRequested);
        if (!armed_ || plainLen > pki_ccm_batch::kProductionMaxPlaintext ||
            outputCapacity < plainLen + pki_ccm_batch::kWireOverhead)
            return false;
        return pki_ccm_batch::encryptProduction(backend_, key, keyLen, nonce, nonceLen, plainLen, plain, crypt, cryptCapacity,
                                                auth, authLen, authCapacity) == pki_ccm_batch::Result::Ok;
    }

    bool decryptPkiCcm(const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
                       std::size_t cryptLen, const std::uint8_t *crypt, const std::uint8_t *auth, std::size_t authLen,
                       std::uint8_t *plain, std::size_t plainCapacity, bool batchRequested) override
    {
        if (!batchRequested)
            return CryptoEngine::decryptPkiCcm(key, keyLen, nonce, nonceLen, cryptLen, crypt, auth, authLen, plain, plainCapacity,
                                               batchRequested);
        if (!armed_ || cryptLen > pki_ccm_batch::kProductionMaxPlaintext)
            return false;
        return pki_ccm_batch::decrypt(backend_, key, keyLen, nonce, nonceLen, cryptLen, crypt, auth, authLen, plain,
                                      plainCapacity) == pki_ccm_batch::Result::Ok;
    }

  private:
    NativeSoftwareAesBackend backend_;
    bool armed_;
};

class ScopedSelectedCrypto
{
  public:
    explicit ScopedSelectedCrypto(CryptoEngine &engine) : previous_(crypto) { crypto = &engine; }
    ~ScopedSelectedCrypto() { crypto = previous_; }

    ScopedSelectedCrypto(const ScopedSelectedCrypto &) = delete;
    ScopedSelectedCrypto &operator=(const ScopedSelectedCrypto &) = delete;

  private:
    CryptoEngine *previous_;
};

bool checkCurveWrapperCapacityAndWire()
{
    std::array<std::uint8_t, 32> privateKey = {
        0xa0, 0x03, 0x30, 0x63, 0x3e, 0x63, 0x52, 0x2f, 0x8a, 0x4d, 0x81, 0xec, 0x6d, 0x9d, 0x1e, 0x66,
        0x17, 0xf6, 0xc8, 0xff, 0xd3, 0xa4, 0xc6, 0x98, 0x22, 0x95, 0x37, 0xd4, 0x4e, 0x52, 0x22, 0x77,
    };
    constexpr std::array<std::uint8_t, 32> remotePublic = {
        0xdb, 0x18, 0xfc, 0x50, 0xee, 0xa4, 0x7f, 0x00, 0x25, 0x1c, 0xb7, 0x84, 0x81, 0x9a, 0x3c, 0xf5,
        0xfc, 0x36, 0x18, 0x82, 0x59, 0x7f, 0x58, 0x9f, 0x0d, 0x7f, 0xf8, 0x20, 0xe8, 0x06, 0x44, 0x57,
    };
    constexpr std::array<std::uint8_t, 10> expectedPlaintext = {0x08, 0x01, 0x12, 0x04, 0x74, 0x65, 0x73, 0x74, 0x48, 0x00};
    constexpr std::array<std::uint8_t, 22> knownWire = {
        0x40, 0xdf, 0x24, 0xab, 0xfc, 0xc3, 0x0a, 0x17, 0xa3, 0xd9, 0x04,
        0x67, 0x26, 0x09, 0x9e, 0x79, 0x6a, 0x1c, 0x03, 0x6a, 0x79, 0x2b,
    };
    constexpr std::uint32_t fromNode = 0x0929;
    constexpr std::uint64_t packetNum = 0x13b2d662;

    SelectedPolicyCryptoEngine inactive(false);
    const std::array<std::uint8_t, pki_ccm_batch::kKeyBytes> inactiveKey = {0};
    const std::array<std::uint8_t, pki_ccm_batch::kNonceBytes> inactiveNonce = {0};
    std::array<std::uint8_t, 32> inactiveCiphertext;
    inactiveCiphertext.fill(0xa5);
    std::array<std::uint8_t, pki_ccm_batch::kTagBytes> inactiveTag;
    inactiveTag.fill(0x5a);
    if (inactive.encryptPkiCcm(inactiveKey.data(), inactiveKey.size(), inactiveNonce.data(), inactiveNonce.size(),
                               expectedPlaintext.size(), expectedPlaintext.data(), inactiveCiphertext.data(),
                               inactiveCiphertext.size(), inactiveTag.data(), inactiveTag.size(), inactiveTag.size(),
                               inactiveCiphertext.size(), true) ||
        !std::all_of(inactiveCiphertext.begin(), inactiveCiphertext.end(), [](std::uint8_t value) { return value == 0xa5; }) ||
        !std::all_of(inactiveTag.begin(), inactiveTag.end(), [](std::uint8_t value) { return value == 0x5a; }))
        return false;

    meshtastic_NodeInfoLite_public_key_t publicKey = {};
    publicKey.size = remotePublic.size();
    std::memcpy(publicKey.bytes, remotePublic.data(), remotePublic.size());

    // Exercise selection through the real wrapper, not only a direct primitive call.
    inactive.setDHPrivateKey(privateKey.data());
    std::array<std::uint8_t, 128> inactiveOutput;
    inactiveOutput.fill(0xa5);
    CcmTimingAggregate inactiveTiming;
    if (inactive.decryptCurve25519(fromNode, publicKey, packetNum, knownWire.size(), knownWire.data(), inactiveOutput.data(),
                                   &inactiveTiming, inactiveOutput.size()) ||
        !allZero(inactiveOutput.data(), inactiveOutput.size()))
        return false;

    SelectedPolicyCryptoEngine engine;
    ScopedSelectedCrypto selected(engine);
    engine.setDHPrivateKey(privateKey.data());

    meshtastic_NodeInfoLite_public_key_t missingPublicKey = {};
    std::array<std::uint8_t, 128> rejectedOutput;
    rejectedOutput.fill(0xa5);
    CcmTimingAggregate rejectedTiming;
    if (engine.decryptCurve25519(fromNode, missingPublicKey, packetNum, knownWire.size(), knownWire.data(), rejectedOutput.data(),
                                 &rejectedTiming, rejectedOutput.size()) ||
        !allZero(rejectedOutput.data(), rejectedOutput.size()))
        return false;

    std::array<std::uint8_t, 128> decrypted;
    decrypted.fill(0xa5);
    CcmTimingAggregate decodeTiming;
    if (!engine.decryptCurve25519(fromNode, publicKey, packetNum, knownWire.size(), knownWire.data(), decrypted.data(),
                                  &decodeTiming, decrypted.size()) ||
        decodeTiming.count != 1 || std::memcmp(decrypted.data(), expectedPlaintext.data(), expectedPlaintext.size()) != 0)
        return false;

    std::uint32_t knownExtraNonce = 0;
    std::memcpy(&knownExtraNonce, knownWire.data() + expectedPlaintext.size() + pki_ccm_batch::kTagBytes,
                sizeof(knownExtraNonce));
    if (std::memcmp(engine.nonce + 4, &knownExtraNonce, sizeof(knownExtraNonce)) != 0)
        return false;

    std::array<std::uint8_t, 9> undersized;
    undersized.fill(0xa5);
    CcmTimingAggregate undersizedTiming;
    if (engine.decryptCurve25519(fromNode, publicKey, packetNum, knownWire.size(), knownWire.data(), undersized.data(),
                                 &undersizedTiming, undersized.size()) ||
        !std::all_of(undersized.begin(), undersized.end(), [](std::uint8_t value) { return value == 0; }))
        return false;

    std::array<std::uint8_t, 128> decryptAlias = {0};
    std::memcpy(decryptAlias.data(), knownWire.data(), knownWire.size());
    const auto decryptAliasBefore = decryptAlias;
    CcmTimingAggregate decryptAliasTiming;
    if (engine.decryptCurve25519(fromNode, publicKey, packetNum, knownWire.size(), decryptAlias.data(), decryptAlias.data(),
                                 &decryptAliasTiming, decryptAlias.size()) ||
        decryptAlias != decryptAliasBefore)
        return false;

    std::array<std::uint8_t, 128> encrypted = {0};
    CcmTimingAggregate encodeTiming;
    if (!engine.encryptCurve25519(0, fromNode, publicKey, packetNum, expectedPlaintext.size(), expectedPlaintext.data(),
                                  encrypted.data(), &encodeTiming, encrypted.size()))
        return false;
    std::uint32_t encryptedExtraNonce = 0;
    std::memcpy(&encryptedExtraNonce, encrypted.data() + expectedPlaintext.size() + pki_ccm_batch::kTagBytes,
                sizeof(encryptedExtraNonce));
    if (std::memcmp(engine.nonce + 4, &encryptedExtraNonce, sizeof(encryptedExtraNonce)) != 0)
        return false;

    std::array<std::uint8_t, 128> encryptAlias = {0};
    std::memcpy(encryptAlias.data(), expectedPlaintext.data(), expectedPlaintext.size());
    const auto encryptAliasBefore = encryptAlias;
    CcmTimingAggregate encryptAliasTiming;
    if (engine.encryptCurve25519(0, fromNode, publicKey, packetNum, expectedPlaintext.size(), encryptAlias.data(),
                                 encryptAlias.data(), &encryptAliasTiming, encryptAlias.size()) ||
        encryptAlias != encryptAliasBefore)
        return false;

    std::array<std::uint8_t, 128> roundTrip;
    roundTrip.fill(0xa5);
    CcmTimingAggregate roundTripTiming;
    if (!engine.decryptCurve25519(fromNode, publicKey, packetNum, expectedPlaintext.size() + pki_ccm_batch::kWireOverhead,
                                  encrypted.data(), roundTrip.data(), &roundTripTiming, roundTrip.size()) ||
        std::memcmp(roundTrip.data(), expectedPlaintext.data(), expectedPlaintext.size()) != 0)
        return false;

    encrypted[0] ^= 1;
    roundTrip.fill(0xa5);
    CcmTimingAggregate tamperedTiming;
    return !engine.decryptCurve25519(fromNode, publicKey, packetNum, expectedPlaintext.size() + pki_ccm_batch::kWireOverhead,
                                     encrypted.data(), roundTrip.data(), &tamperedTiming, roundTrip.size()) &&
           allZero(roundTrip.data(), roundTrip.size());
}

} // namespace
#else
bool checkCurveWrapperCapacityAndWire()
{
    return true;
}
#endif

bool runAll(pki_ccm_batch::AesBackend &batchBackend)
{
    return checkIndependentKat(batchBackend) && compareBoundaries(batchBackend) && checkTamperAndWipe(batchBackend) &&
           checkWireFramingAndCapacity(batchBackend) && checkCurveWrapperCapacityAndWire();
}

#if defined(PIO_UNIT_TESTING)
bool runNativePolicyTests()
{
    NativeSoftwareAesBackend backend;
    return runAll(backend);
}
#endif

} // namespace pki_ccm_batch_firmware_test
