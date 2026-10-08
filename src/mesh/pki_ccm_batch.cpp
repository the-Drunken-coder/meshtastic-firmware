#include "pki_ccm_batch.h"

#include <cstring>
#include <limits>

namespace pki_ccm_batch
{
namespace
{

void secureZero(void *memory, std::size_t length)
{
    volatile std::uint8_t *bytes = static_cast<volatile std::uint8_t *>(memory);
    while (length--)
        *bytes++ = 0;
}

bool constantTimeEqual(const std::uint8_t *left, const std::uint8_t *right, std::size_t length)
{
    const volatile std::uint8_t *volatile leftBytes = left;
    const volatile std::uint8_t *volatile rightBytes = right;
    volatile std::uint8_t difference = 0;
    for (std::size_t i = 0; i < length; ++i)
        difference |= leftBytes[i] ^ rightBytes[i];
    return difference == 0;
}

void buildB0(const std::uint8_t nonce[kNonceBytes], std::size_t length, std::uint8_t block[kBlockBytes])
{
    block[0] = 0x19; // Adata=0, M=8, L=2.
    std::memcpy(block + 1, nonce, kNonceBytes);
    block[14] = static_cast<std::uint8_t>(length >> 8);
    block[15] = static_cast<std::uint8_t>(length);
}

void buildCounter(const std::uint8_t nonce[kNonceBytes], std::uint16_t counter, std::uint8_t block[kBlockBytes])
{
    block[0] = 0x01; // L'=1.
    std::memcpy(block + 1, nonce, kNonceBytes);
    block[14] = static_cast<std::uint8_t>(counter >> 8);
    block[15] = static_cast<std::uint8_t>(counter);
}

std::size_t cbcLength(std::size_t plaintextLength)
{
    return ((kBlockBytes + plaintextLength + kBlockBytes - 1) / kBlockBytes) * kBlockBytes;
}

bool validateKeyNonce(const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen)
{
    return key != nullptr && keyLen == kKeyBytes && nonce != nullptr && nonceLen == kNonceBytes;
}

bool validateLength(std::size_t length)
{
    return length <= kBackendMaxPlaintext;
}

bool validateOutput(std::uint8_t *output, std::size_t capacity, std::size_t required)
{
    // The caller owns the pointer/capacity contract. We can check the
    // declared bound and only ever wipe/write within that declaration.
    return output != nullptr && capacity >= required;
}

bool spansOverlap(const std::uint8_t *left, std::size_t leftLength, const std::uint8_t *right, std::size_t rightLength)
{
    if (leftLength == 0 || rightLength == 0)
        return false;
    const std::uintptr_t leftStart = reinterpret_cast<std::uintptr_t>(left);
    const std::uintptr_t rightStart = reinterpret_cast<std::uintptr_t>(right);
    const std::uintptr_t maximum = std::numeric_limits<std::uintptr_t>::max();
    if (leftLength > maximum - leftStart || rightLength > maximum - rightStart)
        return true;
    const std::uintptr_t leftEnd = leftStart + leftLength;
    const std::uintptr_t rightEnd = rightStart + rightLength;
    return leftStart < rightEnd && rightStart < leftEnd;
}

void wipeOutputs(std::uint8_t *ciphertext, std::size_t ciphertextCapacity, std::uint8_t *tag, std::size_t tagCapacity)
{
    if (ciphertext != nullptr)
        secureZero(ciphertext, ciphertextCapacity);
    if (tag != nullptr)
        secureZero(tag, tagCapacity);
}

void wipePlaintext(std::uint8_t *plaintext, std::size_t plaintextCapacity)
{
    if (plaintext != nullptr)
        secureZero(plaintext, plaintextCapacity);
}

struct OperationCleanup {
    std::uint8_t *cbcInput;
    std::uint8_t *cbcOutput;
    std::uint8_t *a0;
    std::uint8_t *a1;
    std::uint8_t *s0;
    std::uint8_t *temporary;
    std::size_t temporaryLength;
    std::uint8_t *temporary2;
    std::size_t temporary2Length;

    ~OperationCleanup()
    {
        secureZero(cbcInput, kCbcInputScratchBytes);
        secureZero(cbcOutput, kCbcOutputScratchBytes);
        secureZero(a0, kBlockBytes);
        secureZero(a1, kBlockBytes);
        secureZero(s0, kBlockBytes);
        secureZero(temporary, temporaryLength);
        if (temporary2 != nullptr)
            secureZero(temporary2, temporary2Length);
    }
};

struct BackendContextCleanup {
    AesBackend &backend;

    explicit BackendContextCleanup(AesBackend &backend) : backend(backend)
    {
        // A backend object may be reused after an early validation return.
        // Start and finish every public call with a clean local context.
        backend.clear();
    }

    ~BackendContextCleanup() { backend.clear(); }
};

bool computeTag(AesBackend &backend, const std::uint8_t nonce[kNonceBytes], const std::uint8_t *plaintext, std::size_t length,
                std::uint8_t cbcInput[kCbcInputScratchBytes], std::uint8_t cbcOutput[kCbcOutputScratchBytes],
                std::uint8_t a0[kBlockBytes], std::uint8_t tagMask[kBlockBytes], std::uint8_t tag[kTagBytes])
{
    const std::size_t authenticationLength = cbcLength(length);
    std::memset(cbcInput, 0, authenticationLength);

    std::uint8_t b0[kBlockBytes];
    buildB0(nonce, length, b0);
    std::memcpy(cbcInput, b0, sizeof(b0));
    if (length)
        std::memcpy(cbcInput + kBlockBytes, plaintext, length);
    secureZero(b0, sizeof(b0));

    std::uint8_t zeroIv[kBlockBytes] = {0};
    const bool cbcOk = backend.cbcEncrypt(zeroIv, cbcInput, authenticationLength, cbcOutput);
    secureZero(zeroIv, sizeof(zeroIv));
    if (!cbcOk)
        return false;

    buildCounter(nonce, 0, a0);
    if (!backend.ecbEncrypt(a0, tagMask))
        return false;

    const std::uint8_t *x = cbcOutput + authenticationLength - kBlockBytes;
    for (std::size_t i = 0; i < kTagBytes; ++i)
        tag[i] = x[i] ^ tagMask[i];
    return true;
}

// These leaf functions deliberately do not create BackendContextCleanup.
// Each exported wrapper owns the single cleanup layer for the whole operation,
// including wrapper-only validation failures.
Result encryptImpl(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                   std::size_t nonceLen, std::size_t length, const std::uint8_t *plaintext, std::uint8_t *ciphertext,
                   std::size_t ciphertextCapacity, std::uint8_t *tag, std::size_t tagLen, std::size_t tagCapacity)
{
    // All null, fixed-size, and min/max checks happen before any pointer
    // arithmetic. Invalid lengths do not trigger a wipe of an unknown span.
    if (!validateKeyNonce(key, keyLen, nonce, nonceLen) || plaintext == nullptr || ciphertext == nullptr || tag == nullptr ||
        tagLen != kTagBytes)
        return Result::InvalidArgument;
    if (!validateLength(length))
        return Result::InvalidArgument;
    if (!validateOutput(ciphertext, ciphertextCapacity, length) || !validateOutput(tag, tagCapacity, kTagBytes))
        return Result::InsufficientCapacity;
    if (spansOverlap(plaintext, length, ciphertext, ciphertextCapacity) || spansOverlap(plaintext, length, tag, tagCapacity) ||
        spansOverlap(ciphertext, ciphertextCapacity, tag, tagCapacity) ||
        spansOverlap(key, keyLen, ciphertext, ciphertextCapacity) || spansOverlap(key, keyLen, tag, tagCapacity) ||
        spansOverlap(nonce, nonceLen, ciphertext, ciphertextCapacity) || spansOverlap(nonce, nonceLen, tag, tagCapacity))
        return Result::InvalidArgument;

    alignas(kCbcScratchAlignment) std::uint8_t cbcInput[kCbcInputScratchBytes] = {0};
    alignas(kCbcScratchAlignment) std::uint8_t cbcOutput[kCbcOutputScratchBytes] = {0};
    std::uint8_t a0[kBlockBytes] = {0};
    std::uint8_t a1[kBlockBytes] = {0};
    std::uint8_t tagMask[kBlockBytes] = {0};
    std::uint8_t computedTag[kTagBytes] = {0};
    OperationCleanup cleanup{cbcInput, cbcOutput, a0, a1, tagMask, computedTag, sizeof(computedTag), nullptr, 0};

    if (!backend.setKey(key, keyLen)) {
        wipeOutputs(ciphertext, ciphertextCapacity, tag, tagCapacity);
        return Result::BackendError;
    }
    if (!computeTag(backend, nonce, plaintext, length, cbcInput, cbcOutput, a0, tagMask, computedTag)) {
        wipeOutputs(ciphertext, ciphertextCapacity, tag, tagCapacity);
        return Result::BackendError;
    }

    if (length) {
        buildCounter(nonce, 1, a1);
        if (!backend.ctrXor(a1, plaintext, length, ciphertext)) {
            wipeOutputs(ciphertext, ciphertextCapacity, tag, tagCapacity);
            return Result::BackendError;
        }
    }
    std::memcpy(tag, computedTag, kTagBytes);
    return Result::Ok;
}

Result decryptImpl(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                   std::size_t nonceLen, std::size_t length, const std::uint8_t *ciphertext, const std::uint8_t *tag,
                   std::size_t tagLen, std::uint8_t *plaintext, std::size_t plaintextCapacity)
{
    if (!validateKeyNonce(key, keyLen, nonce, nonceLen) || ciphertext == nullptr || tag == nullptr || plaintext == nullptr ||
        tagLen != kTagBytes)
        return Result::InvalidArgument;
    if (!validateLength(length))
        return Result::InvalidArgument;
    if (!validateOutput(plaintext, plaintextCapacity, length))
        return Result::InsufficientCapacity;
    if (spansOverlap(plaintext, plaintextCapacity, ciphertext, length) ||
        spansOverlap(plaintext, plaintextCapacity, tag, tagLen) || spansOverlap(plaintext, plaintextCapacity, key, keyLen) ||
        spansOverlap(plaintext, plaintextCapacity, nonce, nonceLen))
        return Result::InvalidArgument;

    alignas(kCbcScratchAlignment) std::uint8_t cbcInput[kCbcInputScratchBytes] = {0};
    alignas(kCbcScratchAlignment) std::uint8_t cbcOutput[kCbcOutputScratchBytes] = {0};
    std::uint8_t a0[kBlockBytes] = {0};
    std::uint8_t a1[kBlockBytes] = {0};
    std::uint8_t tagMask[kBlockBytes] = {0};
    std::uint8_t plaintextTemporary[kBackendMaxPlaintext] = {0};
    std::uint8_t computedTag[kTagBytes] = {0};
    OperationCleanup cleanup{cbcInput,    cbcOutput,          a0, a1, tagMask, plaintextTemporary, sizeof(plaintextTemporary),
                             computedTag, sizeof(computedTag)};

    if (!backend.setKey(key, keyLen)) {
        wipePlaintext(plaintext, plaintextCapacity);
        return Result::BackendError;
    }
    if (length) {
        buildCounter(nonce, 1, a1);
        if (!backend.ctrXor(a1, ciphertext, length, plaintextTemporary)) {
            wipePlaintext(plaintext, plaintextCapacity);
            return Result::BackendError;
        }
    }
    if (!computeTag(backend, nonce, plaintextTemporary, length, cbcInput, cbcOutput, a0, tagMask, computedTag)) {
        wipePlaintext(plaintext, plaintextCapacity);
        return Result::BackendError;
    }
    if (!constantTimeEqual(computedTag, tag, kTagBytes)) {
        wipePlaintext(plaintext, plaintextCapacity);
        return Result::AuthenticationFailed;
    }
    if (length)
        std::memcpy(plaintext, plaintextTemporary, length);
    return Result::Ok;
}

Result decryptWireImpl(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                       std::size_t nonceLen, std::size_t totalLength, const std::uint8_t *wire, std::size_t wireCapacity,
                       std::uint8_t *plaintext, std::size_t plaintextCapacity)
{
    // Check totalLength before subtracting kWireOverhead. The caller-proven
    // wire capacity also prevents an overread on malformed input.
    if (!validateKeyNonce(key, keyLen, nonce, nonceLen) || plaintext == nullptr || wire == nullptr ||
        totalLength < kWireOverhead || totalLength > kBackendMaxPlaintext + kWireOverhead || wireCapacity < totalLength)
        return Result::InvalidArgument;
    const std::size_t length = totalLength - kWireOverhead;
    if (plaintextCapacity < length)
        return Result::InsufficientCapacity;
    if (spansOverlap(plaintext, plaintextCapacity, wire, wireCapacity))
        return Result::InvalidArgument;
    return decryptImpl(backend, key, keyLen, nonce, nonceLen, length, wire, wire + length, kTagBytes, plaintext,
                       plaintextCapacity);
}

Result encryptProductionImpl(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                             std::size_t nonceLen, std::size_t length, const std::uint8_t *plaintext, std::uint8_t *ciphertext,
                             std::size_t ciphertextCapacity, std::uint8_t *tag, std::size_t tagLen, std::size_t tagCapacity)
{
    if (length > kProductionMaxPlaintext)
        return Result::InvalidArgument;
    return encryptImpl(backend, key, keyLen, nonce, nonceLen, length, plaintext, ciphertext, ciphertextCapacity, tag, tagLen,
                       tagCapacity);
}

Result decryptProductionImpl(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                             std::size_t nonceLen, std::size_t totalLength, const std::uint8_t *wire, std::size_t wireCapacity,
                             std::uint8_t *plaintext, std::size_t plaintextCapacity)
{
    if (totalLength < kWireOverhead || totalLength > kProductionMaxPlaintext + kWireOverhead)
        return Result::InvalidArgument;
    return decryptWireImpl(backend, key, keyLen, nonce, nonceLen, totalLength, wire, wireCapacity, plaintext, plaintextCapacity);
}

} // namespace

Result encrypt(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
               std::size_t length, const std::uint8_t *plaintext, std::uint8_t *ciphertext, std::size_t ciphertextCapacity,
               std::uint8_t *tag, std::size_t tagLen, std::size_t tagCapacity)
{
    BackendContextCleanup contextCleanup(backend);
    return encryptImpl(backend, key, keyLen, nonce, nonceLen, length, plaintext, ciphertext, ciphertextCapacity, tag, tagLen,
                       tagCapacity);
}

Result decrypt(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce, std::size_t nonceLen,
               std::size_t length, const std::uint8_t *ciphertext, const std::uint8_t *tag, std::size_t tagLen,
               std::uint8_t *plaintext, std::size_t plaintextCapacity)
{
    BackendContextCleanup contextCleanup(backend);
    return decryptImpl(backend, key, keyLen, nonce, nonceLen, length, ciphertext, tag, tagLen, plaintext, plaintextCapacity);
}

Result decryptWire(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                   std::size_t nonceLen, std::size_t totalLength, const std::uint8_t *wire, std::size_t wireCapacity,
                   std::uint8_t *plaintext, std::size_t plaintextCapacity)
{
    BackendContextCleanup contextCleanup(backend);
    return decryptWireImpl(backend, key, keyLen, nonce, nonceLen, totalLength, wire, wireCapacity, plaintext, plaintextCapacity);
}

Result encryptProduction(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                         std::size_t nonceLen, std::size_t length, const std::uint8_t *plaintext, std::uint8_t *ciphertext,
                         std::size_t ciphertextCapacity, std::uint8_t *tag, std::size_t tagLen, std::size_t tagCapacity)
{
    BackendContextCleanup contextCleanup(backend);
    return encryptProductionImpl(backend, key, keyLen, nonce, nonceLen, length, plaintext, ciphertext, ciphertextCapacity, tag,
                                 tagLen, tagCapacity);
}

Result decryptProduction(AesBackend &backend, const std::uint8_t *key, std::size_t keyLen, const std::uint8_t *nonce,
                         std::size_t nonceLen, std::size_t totalLength, const std::uint8_t *wire, std::size_t wireCapacity,
                         std::uint8_t *plaintext, std::size_t plaintextCapacity)
{
    BackendContextCleanup contextCleanup(backend);
    return decryptProductionImpl(backend, key, keyLen, nonce, nonceLen, totalLength, wire, wireCapacity, plaintext,
                                 plaintextCapacity);
}

const char *resultName(Result result)
{
    switch (result) {
    case Result::Ok:
        return "ok";
    case Result::InvalidArgument:
        return "invalid_argument";
    case Result::InsufficientCapacity:
        return "insufficient_capacity";
    case Result::BackendError:
        return "backend_error";
    case Result::AuthenticationFailed:
        return "authentication_failed";
    }
    return "unknown";
}

} // namespace pki_ccm_batch
