#pragma once

#include <cstddef>
#include <cstdint>

namespace pki_ccm_batch
{

constexpr std::size_t kBlockBytes = 16;
constexpr std::size_t kKeyBytes = 32;
constexpr std::size_t kNonceBytes = 13;
constexpr std::size_t kTagBytes = 8;
constexpr std::size_t kBackendMaxPlaintext = 239;
constexpr std::size_t kProductionMaxPlaintext = 227;
constexpr std::size_t kWireOverhead = kTagBytes + sizeof(std::uint32_t);
constexpr std::size_t kCbcInputScratchBytes = 256;
constexpr std::size_t kCbcOutputScratchBytes = 256;
constexpr std::size_t kCbcScratchAlignment = kBlockBytes;
constexpr std::size_t kCbcScratchTotalBytes = kCbcInputScratchBytes + kCbcOutputScratchBytes;

enum class Result : std::uint8_t {
    Ok,
    InvalidArgument,
    InsufficientCapacity,
    BackendError,
    AuthenticationFailed,
};

/**
 * Narrow AES mode seam for the bounded PKI CCM operation.
 *
 * An ESP adapter maps these calls to the public mbedTLS CBC, CTR, and ECB
 * APIs. The adapter owns a local AES context for one call and must clear it
 * from clear(). CBC and CTR state must not be shared with ordinary channel
 * encryption. The module has no automatic registration or fallback; the
 * caller must select it explicitly for the PKI path. Since mbedTLS updates
 * its IV and counter arguments, an adapter must copy the const IV/counter
 * inputs into mutable local arrays and never use const_cast.
 */
class AesBackend
{
  public:
    virtual ~AesBackend() = default;

    virtual bool setKey(const std::uint8_t *key, std::size_t keyLen) = 0;
    virtual bool cbcEncrypt(const std::uint8_t iv[kBlockBytes], const std::uint8_t *input, std::size_t length,
                            std::uint8_t *output) = 0;
    virtual bool ctrXor(const std::uint8_t counter[kBlockBytes], const std::uint8_t *input, std::size_t length,
                        std::uint8_t *output) = 0;
    virtual bool ecbEncrypt(const std::uint8_t input[kBlockBytes], std::uint8_t output[kBlockBytes]) = 0;
    virtual void clear() = 0;
};

/**
 * Encrypt exactly length bytes into caller-proven output capacities.
 * ciphertextCapacity is the logical ciphertext slice (length for a contiguous
 * wire buffer), while tagCapacity is the declared tag slice (normally 8).
 * Outputs may not overlap key, nonce, plaintext, or each other.
 */
Result encrypt(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
               std::size_t length, const std::uint8_t *plaintext, std::uint8_t *ciphertext, std::size_t ciphertextCapacity,
               std::uint8_t *tag, std::size_t tagLen, std::size_t tagCapacity);

/**
 * Authenticate before publishing plaintext; wipe the declared plaintext span
 * on backend or authentication failure. The output may not overlap any input.
 */
Result decrypt(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
               std::size_t length, const std::uint8_t *ciphertext, const std::uint8_t *tag, std::size_t tagLen,
               std::uint8_t *plaintext, std::size_t plaintextCapacity);

/**
 * Validate ciphertext || tag || four-byte extraNonce framing before
 * subtracting overhead. wireCapacity is the full caller-declared wire buffer,
 * including any capacity beyond totalLength; plaintext may not overlap that
 * full declared span. An outer packet wrapper owns wiping its full packet
 * output span when that larger capacity is known.
 */
Result decryptWire(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                   std::size_t nonceLen, std::size_t totalLength, const std::uint8_t *wire, std::size_t wireCapacity,
                   std::uint8_t *plaintext, std::size_t plaintextCapacity);

/** Production wrapper with the 227-byte plaintext radio bound. */
Result encryptProduction(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                         std::size_t nonceLen, std::size_t length, const std::uint8_t *plaintext, std::uint8_t *ciphertext,
                         std::size_t ciphertextCapacity, std::uint8_t *tag, std::size_t tagLen, std::size_t tagCapacity);

Result decryptProduction(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                         std::size_t nonceLen, std::size_t totalLength, const std::uint8_t *wire, std::size_t wireCapacity,
                         std::uint8_t *plaintext, std::size_t plaintextCapacity);

const char *resultName(Result result);

} // namespace pki_ccm_batch
