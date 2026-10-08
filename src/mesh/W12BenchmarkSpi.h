#pragma once

#include <cstdint>

namespace w12_benchmark_spi
{

// This selects the requested software clock; physical SCK still requires capture.
#if defined(MESHTASTIC_W12_BENCHMARK_SPI_HZ)
#if !defined(MESHNOLOGY_W12) || !defined(ARCH_ESP32) || (defined(ARCH_PORTDUINO) && ARCH_PORTDUINO) ||                           \
    !defined(MESHTASTIC_W12_BENCHMARK) || !MESHTASTIC_W12_BENCHMARK
#error "MESHTASTIC_W12_BENCHMARK_SPI_HZ requires an ESP32 W12 benchmark build"
#endif
#if MESHTASTIC_W12_BENCHMARK_SPI_HZ != 4000000 && MESHTASTIC_W12_BENCHMARK_SPI_HZ != 8000000
#error "MESHTASTIC_W12_BENCHMARK_SPI_HZ must be 4000000 or 8000000"
#endif
constexpr uint32_t frequencyHz = MESHTASTIC_W12_BENCHMARK_SPI_HZ;
#else
constexpr uint32_t frequencyHz = 4000000;
#endif

} // namespace w12_benchmark_spi
