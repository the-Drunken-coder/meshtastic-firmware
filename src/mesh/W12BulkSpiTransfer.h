#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace w12_bulk_spi
{

constexpr size_t MAX_FIFO_CHUNK_BYTES = 64;
constexpr size_t WORD_BYTES = sizeof(uint32_t);

static_assert(WORD_BYTES == 4, "W12 bulk SPI requires 32-bit words");

// Arduino-ESP32's transaction-path bulk transfer reads whole words, so keep its input aligned and
// make its length a multiple of four. The remaining bytes use the byte-transfer path.
template <typename Spi> void transfer(Spi &spi, const uint8_t *out, size_t len, uint8_t *in)
{
    alignas(uint32_t) uint32_t txWords[MAX_FIFO_CHUNK_BYTES / WORD_BYTES];
    alignas(uint32_t) uint32_t rxWords[MAX_FIFO_CHUNK_BYTES / WORD_BYTES];

    while (len >= WORD_BYTES) {
        size_t bulkLen = len & ~(WORD_BYTES - 1);
        if (bulkLen > MAX_FIFO_CHUNK_BYTES)
            bulkLen = MAX_FIFO_CHUNK_BYTES;

        std::memcpy(txWords, out, bulkLen);
        std::memset(rxWords, 0, bulkLen);
        spi.transferBytes(reinterpret_cast<const uint8_t *>(txWords), reinterpret_cast<uint8_t *>(rxWords), bulkLen);
        std::memcpy(in, rxWords, bulkLen);

        out += bulkLen;
        in += bulkLen;
        len -= bulkLen;
    }

    while (len != 0) {
        *in++ = spi.transfer(*out++);
        --len;
    }
}

} // namespace w12_bulk_spi
