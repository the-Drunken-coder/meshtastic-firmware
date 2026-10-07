// Tests for the W12 bulk SPI transfer seam. Arduino-ESP32 3.3.11's transaction-path bulk
// implementation copies transmit data as 32-bit words and rounds partial lengths up, so a direct
// transfer of a 257-byte RadioLib frame can read past its buffer. The helper must present only
// aligned, four-byte-sized chunks to that path, use byte transfers for the tail, preserve exact
// caller bounds, and keep transaction and CS ownership outside the helper.

#include "TestUtil.h"
#include "W12BulkSpiTransfer.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <unity.h>

#if defined(ARCH_PORTDUINO)
#define W12_BULK_TEST_ENTRY extern "C"
#else
#define W12_BULK_TEST_ENTRY
#endif

namespace
{

constexpr uint8_t kBulkXor = 0xA5;
constexpr size_t kMaxTransfer = 258;

struct CoreLikeSpi {
    size_t bulkCalls = 0;
    size_t byteCalls = 0;
    size_t bulkLengths[16] = {};
    size_t invalidCalls = 0;
    bool bulkBuffersAligned = true;

    // This seam exposes only transfer operations; transaction and CS ownership remain with the
    // LockingArduinoHal caller and cannot be mutated by the helper.

    void transferBytes(const uint8_t *data, uint8_t *out, uint32_t size)
    {
        const bool aligned = reinterpret_cast<uintptr_t>(data) % alignof(uint32_t) == 0 &&
                             reinterpret_cast<uintptr_t>(out) % alignof(uint32_t) == 0;
        if (!aligned)
            bulkBuffersAligned = false;

        const bool valid =
            size != 0 && size <= w12_bulk_spi::MAX_FIFO_CHUNK_BYTES && size % w12_bulk_spi::WORD_BYTES == 0 && aligned;
        if (!valid) {
            ++invalidCalls;
            if (!aligned || size == 0)
                return;
        }

        // Match the core's rounded-up word loads for invalid calls so an unsafe full-length call
        // on an exact-sized heap buffer remains visible to ASan.
        const size_t words = (size + sizeof(uint32_t) - 1) / sizeof(uint32_t);
        const uint32_t *dataWords = reinterpret_cast<const uint32_t *>(data);
        uint32_t *outWords = reinterpret_cast<uint32_t *>(out);
        for (size_t i = 0; i < words; ++i)
            outWords[i] = dataWords[i] ^ 0xA5A5A5A5u;

        if (!valid)
            return;

        TEST_ASSERT_LESS_THAN(sizeof(bulkLengths) / sizeof(bulkLengths[0]), bulkCalls);
        bulkLengths[bulkCalls++] = size;
    }

    uint8_t transfer(uint8_t data)
    {
        ++byteCalls;
        return data ^ kBulkXor;
    }
};

void assertTransferContract(const CoreLikeSpi &spi, size_t len)
{
    size_t transferred = spi.byteCalls;
    for (size_t i = 0; i < spi.bulkCalls; ++i) {
        TEST_ASSERT_GREATER_THAN_UINT32(0, spi.bulkLengths[i]);
        TEST_ASSERT_LESS_OR_EQUAL_UINT32(w12_bulk_spi::MAX_FIFO_CHUNK_BYTES, spi.bulkLengths[i]);
        TEST_ASSERT_EQUAL_UINT32(0, spi.bulkLengths[i] % w12_bulk_spi::WORD_BYTES);
        transferred += spi.bulkLengths[i];
    }
    TEST_ASSERT_EQUAL_UINT32(len, transferred);
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(3, spi.byteCalls);
    if (len >= w12_bulk_spi::WORD_BYTES)
        TEST_ASSERT_GREATER_THAN_UINT32(0, spi.bulkCalls);
    else
        TEST_ASSERT_EQUAL_UINT32(0, spi.bulkCalls);
    TEST_ASSERT_EQUAL_UINT32(0, spi.invalidCalls);
    TEST_ASSERT_TRUE(spi.bulkBuffersAligned);
}

void fillPayload(uint8_t *payload, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        payload[i] = static_cast<uint8_t>(0x20u + (i * 37u));
}

void assertTransformed(const uint8_t *input, const uint8_t *output, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        TEST_ASSERT_EQUAL_UINT8(input[i] ^ kBulkXor, output[i]);
}

void test_all_lengths_use_safe_core_shapes_and_exact_bounds()
{
    constexpr size_t lengths[] = {0, 1, 2, 3, 4, 63, 64, 65, 255, 257, 258};

    for (size_t len : lengths) {
        CoreLikeSpi spi;
        alignas(uint32_t) std::array<uint8_t, kMaxTransfer + 8> inputStorage;
        alignas(uint32_t) std::array<uint8_t, kMaxTransfer + 8> outputStorage;
        inputStorage.fill(0xC1);
        outputStorage.fill(0xD2);
        uint8_t *input = inputStorage.data() + 3;
        uint8_t *output = outputStorage.data() + 1;
        TEST_ASSERT_NOT_EQUAL_UINT32(0, reinterpret_cast<uintptr_t>(input) % alignof(uint32_t));
        TEST_ASSERT_NOT_EQUAL_UINT32(0, reinterpret_cast<uintptr_t>(output) % alignof(uint32_t));
        fillPayload(input, len);

        w12_bulk_spi::transfer(spi, input, len, output);

        assertTransferContract(spi, len);
        assertTransformed(input, output, len);
        TEST_ASSERT_EQUAL_UINT8(0xC1, inputStorage.front());
        TEST_ASSERT_EQUAL_UINT8(0xC1, inputStorage.back());
        for (size_t i = 0; i < outputStorage.size(); ++i) {
            if (i < 1 || i >= 1 + len)
                TEST_ASSERT_EQUAL_UINT8(0xD2, outputStorage[i]);
        }
    }
}

void test_exact_257_byte_heap_input_has_no_overread()
{
    CoreLikeSpi spi;
    constexpr size_t len = 257;
    std::unique_ptr<uint8_t[]> input(new uint8_t[len]);
    std::unique_ptr<uint8_t[]> output(new uint8_t[len + 3]);
    fillPayload(input.get(), len);
    std::memset(output.get(), 0xD2, len + 3);

    w12_bulk_spi::transfer(spi, input.get(), len, output.get());

    assertTransferContract(spi, len);
    assertTransformed(input.get(), output.get(), len);
    for (size_t i = len; i < len + 3; ++i)
        TEST_ASSERT_EQUAL_UINT8(0xD2, output[i]);
}

struct NoWriteSpi {
    size_t bulkCalls = 0;
    size_t byteCalls = 0;

    void transferBytes(const uint8_t *, uint8_t *out, uint32_t size)
    {
        ++bulkCalls;
        if (bulkCalls == 1)
            std::memset(out, 0x5A, size);
    }

    uint8_t transfer(uint8_t)
    {
        ++byteCalls;
        return 0;
    }
};

void test_no_write_bulk_leaves_deterministic_zero_output()
{
    NoWriteSpi spi;
    constexpr size_t len = 129;
    std::array<uint8_t, len> input = {};
    std::array<uint8_t, len> output;
    output.fill(0xD2);

    w12_bulk_spi::transfer(spi, input.data(), len, output.data());

    TEST_ASSERT_EQUAL_UINT32(2, spi.bulkCalls);
    TEST_ASSERT_EQUAL_UINT32(1, spi.byteCalls);
    for (size_t i = 0; i < 64; ++i)
        TEST_ASSERT_EQUAL_UINT8(0x5A, output[i]);
    for (size_t i = 64; i < len; ++i)
        TEST_ASSERT_EQUAL_UINT8(0, output[i]);
}

void test_exact_aliasing_is_safe()
{
    CoreLikeSpi spi;
    alignas(uint32_t) std::array<uint8_t, kMaxTransfer + 8> storage;
    storage.fill(0xE3);
    uint8_t *payload = storage.data() + 3;
    TEST_ASSERT_NOT_EQUAL_UINT32(0, reinterpret_cast<uintptr_t>(payload) % alignof(uint32_t));
    fillPayload(payload, kMaxTransfer);
    std::array<uint8_t, kMaxTransfer> expected;
    std::memcpy(expected.data(), payload, expected.size());

    w12_bulk_spi::transfer(spi, payload, expected.size(), payload);

    assertTransformed(expected.data(), payload, expected.size());
    TEST_ASSERT_EQUAL_UINT32(0, spi.invalidCalls);
    TEST_ASSERT_EQUAL_UINT8(0xE3, storage.front());
    TEST_ASSERT_EQUAL_UINT8(0xE3, storage.back());
}

} // namespace

void setUp() {}
void tearDown() {}

W12_BULK_TEST_ENTRY void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_all_lengths_use_safe_core_shapes_and_exact_bounds);
    RUN_TEST(test_exact_257_byte_heap_input_has_no_overread);
    RUN_TEST(test_no_write_bulk_leaves_deterministic_zero_output);
    RUN_TEST(test_exact_aliasing_is_safe);
    exit(UNITY_END());
}

W12_BULK_TEST_ENTRY void loop() {}
