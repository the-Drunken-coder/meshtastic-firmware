#include "MeshRadio.h"
#include "MeshService.h"
#include "PhoneAPI.h"
#include "RadioInterface.h"
#include "Router.h"
#include "TestUtil.h"
#include <memory>
#include <unity.h>
#include <vector>

namespace
{
class PhoneIngressShim : public PhoneAPI
{
  public:
    std::vector<std::vector<uint8_t>> deliveries;
    bool enqueueDuringFirstDelivery = false;
    bool reentrantEnqueueAccepted = false;
    bool invokeNestedDrain = false;
    size_t reentrantEnqueuesRemaining = 0;

    bool checkIsConnected() override { return true; }

    bool handleToRadio(const uint8_t *buf, size_t len) override
    {
        deliveries.emplace_back(buf, buf + len);
        if (enqueueDuringFirstDelivery && deliveries.size() == 1) {
            const uint8_t followUp[] = {0xf0, 0x0d};
            reentrantEnqueueAccepted = enqueueToRadio(followUp, sizeof(followUp));
        }
        if (invokeNestedDrain && deliveries.size() == 1)
            PhoneAPI::drainForeignToRadio();
        if (reentrantEnqueuesRemaining > 0) {
            const uint8_t followUp[] = {0xee};
            reentrantEnqueueAccepted = enqueueToRadio(followUp, sizeof(followUp));
            --reentrantEnqueuesRemaining;
        }
        return true;
    }
};

class IngressRadioInterface : public RadioInterface
{
  public:
    ErrorCode send(meshtastic_MeshPacket *packet) override
    {
        packetPool.release(packet);
        return ERRNO_OK;
    }

    meshtastic_QueueStatus getQueueStatus() override
    {
        meshtastic_QueueStatus status = meshtastic_QueueStatus_init_zero;
        status.free = MAX_TX_QUEUE;
        status.maxlen = MAX_TX_QUEUE;
        return status;
    }

    uint32_t getPacketTime(uint32_t, bool) override { return 0; }
};

class IngressRouter : public Router
{
  public:
    IngressRouter() { addInterface(std::make_unique<IngressRadioInterface>()); }

    ErrorCode send(meshtastic_MeshPacket *packet) override
    {
        packetPool.release(packet);
        return ERRNO_OK;
    }
};

MeshService *testService = nullptr;
MeshService *savedService = nullptr;
IngressRouter *testRouter = nullptr;
Router *savedRouter = nullptr;

void clearIngress()
{
    PhoneAPI::drainForeignToRadio();
}

void test_foreign_ingress_copies_and_preserves_fifo()
{
    PhoneIngressShim api;
    uint8_t first[] = {1, 2, 3};
    const uint8_t second[] = {4, 5};

    TEST_ASSERT_TRUE(api.enqueueToRadio(first, sizeof(first)));
    first[0] = 0xff;
    TEST_ASSERT_TRUE(api.enqueueToRadio(second, sizeof(second)));

    PhoneAPI::drainForeignToRadio();

    TEST_ASSERT_EQUAL_UINT(2, api.deliveries.size());
    const uint8_t expectedFirst[] = {1, 2, 3};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expectedFirst, api.deliveries[0].data(), sizeof(expectedFirst));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(second, api.deliveries[1].data(), sizeof(second));
}

void test_mesh_service_loop_drains_foreign_ingress()
{
    PhoneIngressShim api;
    const uint8_t payload[] = {0x61, 0x62};
    TEST_ASSERT_TRUE(api.enqueueToRadio(payload, sizeof(payload)));

    testService->loop();

    TEST_ASSERT_EQUAL_UINT(1, api.deliveries.size());
    TEST_ASSERT_EQUAL_UINT8_ARRAY(payload, api.deliveries[0].data(), sizeof(payload));
}

void test_foreign_ingress_rejects_bounded_overflow()
{
    PhoneIngressShim api;
    const uint8_t payload[] = {0x42};

    for (size_t i = 0; i < 4; ++i)
        TEST_ASSERT_TRUE(api.enqueueToRadio(payload, sizeof(payload)));
    TEST_ASSERT_FALSE(api.enqueueToRadio(payload, sizeof(payload)));

    PhoneAPI::drainForeignToRadio();
    TEST_ASSERT_EQUAL_UINT(4, api.deliveries.size());
}

void test_foreign_ingress_purges_destroyed_target()
{
    auto *expired = new PhoneIngressShim();
    const uint8_t payload[] = {0x11};
    TEST_ASSERT_TRUE(expired->enqueueToRadio(payload, sizeof(payload)));
    delete expired;

    PhoneIngressShim survivor;
    PhoneAPI::drainForeignToRadio();
    TEST_ASSERT_TRUE(survivor.deliveries.empty());
}

void test_foreign_ingress_drops_writes_after_disconnect()
{
    PhoneIngressShim api;
    const uint8_t payload[] = {0x22};
    TEST_ASSERT_TRUE(api.enqueueToRadio(payload, sizeof(payload)));
    api.close();

    PhoneAPI::drainForeignToRadio();
    TEST_ASSERT_TRUE(api.deliveries.empty());
}

void test_foreign_close_runs_on_owner_and_reopens_ingress()
{
    PhoneIngressShim api;
    const uint8_t oldPayload[] = {0x31};
    const uint8_t newPayload[] = {0x32};
    TEST_ASSERT_TRUE(api.enqueueToRadio(oldPayload, sizeof(oldPayload)));

    api.requestCloseFromForeign();
    TEST_ASSERT_TRUE(api.hasPendingForeignClose());
    PhoneAPI::drainForeignToRadio();
    TEST_ASSERT_FALSE(api.hasPendingForeignClose());
    TEST_ASSERT_TRUE(api.deliveries.empty());

    TEST_ASSERT_TRUE(api.enqueueToRadio(newPayload, sizeof(newPayload)));
    PhoneAPI::drainForeignToRadio();
    TEST_ASSERT_EQUAL_UINT(1, api.deliveries.size());
    TEST_ASSERT_EQUAL_UINT8(0x32, api.deliveries[0][0]);
}

void test_foreign_ingress_allows_reentrant_enqueue()
{
    PhoneIngressShim api;
    api.enqueueDuringFirstDelivery = true;
    const uint8_t payload[] = {0x10};
    TEST_ASSERT_TRUE(api.enqueueToRadio(payload, sizeof(payload)));

    PhoneAPI::drainForeignToRadio();

    TEST_ASSERT_TRUE(api.reentrantEnqueueAccepted);
    TEST_ASSERT_EQUAL_UINT(2, api.deliveries.size());
    TEST_ASSERT_EQUAL_UINT8(0x10, api.deliveries[0][0]);
    TEST_ASSERT_EQUAL_UINT8(0xf0, api.deliveries[1][0]);
}

void test_foreign_ingress_rejects_nested_drain_and_bounds_a_pass()
{
    PhoneIngressShim api;
    api.invokeNestedDrain = true;
    api.reentrantEnqueuesRemaining = 8;
    const uint8_t payload[] = {0x10};
    TEST_ASSERT_TRUE(api.enqueueToRadio(payload, sizeof(payload)));

    PhoneAPI::drainForeignToRadio();
    TEST_ASSERT_EQUAL_UINT(4, api.deliveries.size());

    PhoneAPI::drainForeignToRadio();
    PhoneAPI::drainForeignToRadio();
    TEST_ASSERT_EQUAL_UINT(9, api.deliveries.size());
}
} // namespace

void setUp()
{
    savedService = service;
    savedRouter = router;
    if (!testService)
        testService = new MeshService();
    initRegion();
    testRouter = new IngressRouter();
    service = testService;
    router = testRouter;
    clearIngress();
}

void tearDown()
{
    clearIngress();
    service = savedService;
    router = savedRouter;
    delete testRouter;
    testRouter = nullptr;
}

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_foreign_ingress_copies_and_preserves_fifo);
    RUN_TEST(test_mesh_service_loop_drains_foreign_ingress);
    RUN_TEST(test_foreign_ingress_rejects_bounded_overflow);
    RUN_TEST(test_foreign_ingress_purges_destroyed_target);
    RUN_TEST(test_foreign_ingress_drops_writes_after_disconnect);
    RUN_TEST(test_foreign_close_runs_on_owner_and_reopens_ingress);
    RUN_TEST(test_foreign_ingress_allows_reentrant_enqueue);
    RUN_TEST(test_foreign_ingress_rejects_nested_drain_and_bounds_a_pass);
    exit(UNITY_END());
}

void loop() {}
