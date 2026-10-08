#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#ifndef MESHTASTIC_W12_BENCHMARK_HAL_TIMING
#define MESHTASTIC_W12_BENCHMARK_HAL_TIMING 0
#endif

#define W12_BENCHMARK_HAL_TIMING_ENABLED                                                                                         \
    (MESHTASTIC_W12_BENCHMARK && MESHTASTIC_W12_BENCHMARK_PHASE_TIMING && MESHTASTIC_W12_BENCHMARK_HAL_TIMING)

/**
 * Owner-thread snapshot of the scalar HAL cost counters. The measured window starts after an
 * accepted START and ends after finishRun's abort/stop work plus the final owned pending-terminal
 * callback. Post-callback packetReleased/packetPool release and final RX rearm work are outside
 * the window. Other HAL activity during the active run is included; these counters are not a
 * payload-only or whole-software timing total. The collector is deliberately lock-free: HAL
 * callbacks run on the radio worker, while begin/freeze/get run on that same owner path.
 */
class W12BenchmarkHalMetrics
{
  public:
    struct Snapshot {
        uint32_t requestedHz = 0;
        uint32_t transferCount = 0;
        uint64_t transferredBytes = 0;
        uint64_t transferSumUs = 0;
        uint32_t transferMaxUs = 0;
        uint32_t yieldCount = 0;
        uint64_t yieldSumUs = 0;
        uint32_t yieldMaxUs = 0;
        bool frozen = false;
        bool overflow = false;
    };

    void begin()
    {
        snapshot = Snapshot{};
        snapshot.requestedHz = requestedHz;
        collecting = true;
    }

    void reset()
    {
        snapshot = Snapshot{};
        snapshot.requestedHz = requestedHz;
        collecting = false;
    }

    void freeze()
    {
        if (collecting) {
            collecting = false;
            snapshot.frozen = true;
        }
    }

    Snapshot get() const { return snapshot; }

  private:
    friend class LockingArduinoHal;
    friend class W12BenchmarkHalMetricsTestAccess;

    void setRequestedHz(uint32_t value)
    {
        requestedHz = value;
        snapshot.requestedHz = value;
    }

    bool isCollecting() const { return collecting; }

    void recordTransfer(uint32_t durationUs, size_t logicalBytes)
    {
        increment(snapshot.transferCount);
        add(snapshot.transferredBytes, static_cast<uint64_t>(logicalBytes));
        add(snapshot.transferSumUs, durationUs);
        if (durationUs > snapshot.transferMaxUs)
            snapshot.transferMaxUs = durationUs;
    }

    void recordYield(uint32_t durationUs)
    {
        increment(snapshot.yieldCount);
        add(snapshot.yieldSumUs, durationUs);
        if (durationUs > snapshot.yieldMaxUs)
            snapshot.yieldMaxUs = durationUs;
    }

    void increment(uint32_t &value)
    {
        if (value == std::numeric_limits<uint32_t>::max()) {
            snapshot.overflow = true;
            return;
        }
        ++value;
    }

    void add(uint64_t &value, uint64_t amount)
    {
        if (std::numeric_limits<uint64_t>::max() - value < amount) {
            value = std::numeric_limits<uint64_t>::max();
            snapshot.overflow = true;
            return;
        }
        value += amount;
    }

    uint32_t requestedHz = 0;
    Snapshot snapshot;
    bool collecting = false;
};
