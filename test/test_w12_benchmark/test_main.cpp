#include "MeshRadio.h"
#include "MeshTypes.h"
#include "NodeStatus.h"
#include "TestUtil.h"
#include "UptimeClock.h"
#include "airtime.h"
#include "mesh/CryptoEngine.h"
#include "mesh/MeshService.h"
#include "mesh/NodeDB.h"
#include "mesh/RadioInterface.h"
#include "mesh/RadioLibInterface.h"
#include "mesh/ReliableRouter.h"
#include "modules/RoutingModule.h"
#include "modules/W12BenchmarkModule.h"
#include "mqtt/MQTT.h"
#include <cstring>
#include <memory>
#include <unity.h>
#include <vector>

#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)

namespace
{
static constexpr NodeNum kSource = 0x11111111;
static constexpr NodeNum kDestination = 0x22222222;

W12BenchmarkModule::RunConfig runConfig()
{
    W12BenchmarkModule::RunConfig c;
    c.runId = 0x10203040;
    c.source = kSource;
    c.destination = kDestination;
    c.count = 1000;
    c.size = W12BenchmarkModule::DEFAULT_SIZE;
    c.durationMs = 60000;
    c.window = 16;
    return c;
}

uint32_t read32(const uint8_t *bytes, size_t offset)
{
    return static_cast<uint32_t>(bytes[offset]) | static_cast<uint32_t>(bytes[offset + 1]) << 8 |
           static_cast<uint32_t>(bytes[offset + 2]) << 16 | static_cast<uint32_t>(bytes[offset + 3]) << 24;
}

int16_t read16s(const uint8_t *bytes, size_t offset)
{
    return static_cast<int16_t>(static_cast<uint16_t>(bytes[offset]) | static_cast<uint16_t>(bytes[offset + 1]) << 8);
}

class BenchmarkNodeDB : public NodeDB
{
  public:
    void clearTestNodes()
    {
        testNodes.clear();
        meshNodes = &testNodes;
        numMeshNodes = 0;
    }

    void addPublicKey(NodeNum num, const uint8_t *key)
    {
        meshtastic_NodeInfoLite node = meshtastic_NodeInfoLite_init_zero;
        node.num = num;
        node.public_key.size = 32;
        memcpy(node.public_key.bytes, key, 32);
        testNodes.push_back(node);
        meshNodes = &testNodes;
        numMeshNodes = testNodes.size();
    }

  private:
    std::vector<meshtastic_NodeInfoLite> testNodes;
};

class BenchmarkRadio : public RadioInterface
{
  public:
    ErrorCode send(meshtastic_MeshPacket *packet) override
    {
        pending.push_back(packet);
        if (w12BenchmarkModule)
            w12BenchmarkModule->onTxStarted(packet);
        return ERRNO_OK;
    }

    meshtastic_QueueStatus getQueueStatus() override
    {
        meshtastic_QueueStatus status = meshtastic_QueueStatus_init_zero;
        status.maxlen = 16;
        status.free = pending.size() < status.maxlen ? status.maxlen - pending.size() : 0;
        return status;
    }

    uint32_t getPacketTime(uint32_t, bool = false) override { return 0; }

    meshtastic_MeshPacket *pendingAt(size_t index) const { return pending.at(index); }
    size_t pendingCount() const { return pending.size(); }

    void callbackAt(size_t index, RadioInterface::TxState state)
    {
        if (w12BenchmarkModule)
            w12BenchmarkModule->onTxFinished(pending.at(index), state);
    }

    void releaseAt(size_t index)
    {
        packetPool.release(pending.at(index));
        pending.erase(pending.begin() + index);
    }

    void finishAt(size_t index, RadioInterface::TxState state)
    {
        callbackAt(index, state);
        releaseAt(index);
    }

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    void finishAtWithOwnerTxNotification(size_t index, uint32_t startedAtUs, bool owned = true, bool valid = true)
    {
        if (w12BenchmarkModule)
            w12BenchmarkModule->onOwnerTxNotification(startedAtUs, owned, valid);
        finishAt(index, valid ? RadioInterface::TxState::Sent : RadioInterface::TxState::Failed);
    }
#endif

    void releaseAll()
    {
        while (!pending.empty())
            finishAt(pending.size() - 1, RadioInterface::TxState::Cancelled);
    }

  private:
    std::vector<meshtastic_MeshPacket *> pending;
};

class BenchmarkDiagnosticRadio : public RadioLibInterface
{
  public:
    BenchmarkDiagnosticRadio() : RadioLibInterface(nullptr, 0, 0, 0, 0) {}

    bool isChannelActive() override { return false; }
    bool isActivelyReceiving() override { return false; }
    uint32_t getPacketTime(uint32_t, bool = false) override { return 0; }
    int16_t getCurrentRSSI() override { return -100; }
    void addReceiveMetadata(meshtastic_MeshPacket *) override {}
    void setRadioIsr(void (*)()) override {}
    void clearRadioIsr() override {}
    bool isSending() override { return sending; }
    void startReceive() override { ++startReceiveCalls; }

    bool performW12RxRearm(W12RxRearmResult &result) override
    {
        result = W12RxRearmResult{};
        if (sending)
            return false;
        result.beforeState = getW12DiagnosticRadioState();
        const uint32_t startedAt = micros();
        startReceive();
        result.durationUs = static_cast<uint32_t>(micros() - startedAt);
        result.afterState = getW12DiagnosticRadioState();
        result.softwareArmed = false;
        return true;
    }

    bool readW12RxLiveness(W12RxLivenessSample &sample) override
    {
        sample = scriptedSample;
        return true;
    }

    W12RxLivenessSample scriptedSample;
    uint32_t startReceiveCalls = 0;
    bool sending = false;
};

class BenchmarkRouter : public ReliableRouter
{
};

class BenchmarkRoutingModule : public RoutingModule
{
  public:
    void sendAckNak(meshtastic_Routing_Error, NodeNum, PacketId, ChannelIndex, uint8_t = 0, bool = false,
                    const meshtastic_MeshPacket * = nullptr) override
    {
    }
};

class BenchmarkModuleShim : public W12BenchmarkModule
{
  public:
    using W12BenchmarkModule::allocReply;
    using W12BenchmarkModule::handleReceived;
    using W12BenchmarkModule::runOnce;
};

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
class RouterBatchSelectionProbe final : public CryptoEngine
{
  public:
    bool pkiCcmBatchEnabled() const override { return true; }

    bool decryptPkiCcm(const uint8_t *key, size_t keyLen, const uint8_t *nonce, size_t nonceLen, size_t cryptLen,
                       const uint8_t *crypt, const uint8_t *auth, size_t authLen, uint8_t *plain, size_t plainCapacity,
                       bool batchRequested) override
    {
        if (batchRequested)
            sawBatchRequested = true;
        // Keep the production decrypt operation while observing only which caller path was selected.
        return CryptoEngine::decryptPkiCcm(key, keyLen, nonce, nonceLen, cryptLen, crypt, auth, authLen, plain, plainCapacity,
                                           false);
    }

    void clearSelection() { sawBatchRequested = false; }

    bool sawBatchRequested = false;
};
#endif

static BenchmarkNodeDB *testNodeDB = nullptr;
static BenchmarkRouter *testRouter = nullptr;
static BenchmarkRadio *testRadio = nullptr;
static BenchmarkRoutingModule *testRouting = nullptr;
static MeshService *testService = nullptr;
static BenchmarkModuleShim *testModule = nullptr;
static AirTime *savedAirTime = nullptr;
static meshtastic::NodeStatus *savedNodeStatus = nullptr;
static NodeDB *savedNodeDB = nullptr;
static Router *savedRouter = nullptr;
static MeshService *savedService = nullptr;
static RoutingModule *savedRouting = nullptr;
static MQTT *savedMqtt = nullptr;

static meshtastic_MeshPacket
makeControl(const W12BenchmarkModule::RunConfig &run, W12BenchmarkModule::Op op, NodeNum localNode,
            meshtastic_MeshPacket_TransportMechanism transport = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL,
            NodeNum from = 0)
{
    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_zero;
    packet.from = from;
    packet.to = localNode;
    packet.transport_mechanism = transport;
    packet.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    packet.decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
    packet.decoded.payload.size =
        W12BenchmarkModule::encodeControl(packet.decoded.payload.bytes, sizeof(packet.decoded.payload.bytes), op, run);
    return packet;
}

static meshtastic_MeshPacket
makeData(const W12BenchmarkModule::RunConfig &run, uint32_t sequence,
         meshtastic_MeshPacket_TransportMechanism transport = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA,
         bool pki = true, bool viaMqtt = false)
{
    meshtastic_MeshPacket packet = meshtastic_MeshPacket_init_zero;
    packet.from = run.source;
    packet.to = run.destination;
    packet.id = 0x60000000u + sequence;
    packet.transport_mechanism = transport;
    packet.pki_encrypted = pki;
    packet.via_mqtt = viaMqtt;
    packet.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    packet.decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
    packet.decoded.payload.size =
        W12BenchmarkModule::encodeData(packet.decoded.payload.bytes, sizeof(packet.decoded.payload.bytes), run, sequence);
    return packet;
}

static void preparePkiFixture()
{
    uint8_t localPublic[32] = {};
    uint8_t localPrivate[32] = {};
    uint8_t destinationPublic[32] = {};
    uint8_t destinationPrivate[32] = {};
    crypto->generateKeyPair(localPublic, localPrivate);
    crypto->generateKeyPair(destinationPublic, destinationPrivate);
    testNodeDB->addPublicKey(kDestination, destinationPublic);
    config.security.private_key.size = 32;
    config.security.public_key.size = 32;
    memcpy(config.security.private_key.bytes, localPrivate, sizeof(localPrivate));
    memcpy(config.security.public_key.bytes, localPublic, sizeof(localPublic));
    crypto->setDHPrivateKey(localPrivate);
}

static ProcessMessage
sendControl(const W12BenchmarkModule::RunConfig &run, W12BenchmarkModule::Op op, NodeNum localNode,
            meshtastic_MeshPacket_TransportMechanism transport = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL,
            NodeNum from = 0)
{
    return testModule->handleReceived(makeControl(run, op, localNode, transport, from));
}

static void createFixture()
{
    savedAirTime = airTime;
    savedNodeStatus = nodeStatus;
    savedNodeDB = nodeDB;
    savedRouter = router;
    savedService = service;
    savedRouting = routingModule;
    savedMqtt = mqtt;

    airTime = new AirTime();
    nodeStatus = new meshtastic::NodeStatus();
    config = meshtastic_LocalConfig_init_zero;
    moduleConfig = meshtastic_LocalModuleConfig_init_zero;
    owner = meshtastic_User_init_zero;
    myNodeInfo = meshtastic_MyNodeInfo_init_zero;
    myNodeInfo.my_node_num = kSource;
    config.lora.region = meshtastic_Config_LoRaConfig_RegionCode_US;
    initRegion();

    testNodeDB = new BenchmarkNodeDB();
    testNodeDB->clearTestNodes();
    nodeDB = testNodeDB;
    testRouter = new BenchmarkRouter();
    auto radio = std::make_unique<BenchmarkRadio>();
    testRadio = radio.get();
    testRouter->addInterface(std::move(radio));
    router = testRouter;
    testRouting = new BenchmarkRoutingModule();
    routingModule = testRouting;
    testService = new MeshService();
    service = testService;
    mqtt = nullptr;
}

static void destroyFixture()
{
    if (testRadio)
        testRadio->releaseAll();
    delete testModule;
    testModule = nullptr;
    w12BenchmarkModule = nullptr;
    delete testService;
    testService = nullptr;
    delete testRouting;
    testRouting = nullptr;
    delete testRouter;
    testRouter = nullptr;
    testRadio = nullptr;
    delete testNodeDB;
    testNodeDB = nullptr;

    delete airTime;
    delete nodeStatus;
    airTime = savedAirTime;
    nodeStatus = savedNodeStatus;
    nodeDB = savedNodeDB;
    router = savedRouter;
    service = savedService;
    routingModule = savedRouting;
    mqtt = savedMqtt;
    Time::useRealClock();
    Time::resetMonotonicForTests();
}

static void resetTestState()
{
    if (testRadio)
        testRadio->releaseAll();
    delete testModule;
    testModule = nullptr;
    w12BenchmarkModule = nullptr;

    config = meshtastic_LocalConfig_init_zero;
    moduleConfig = meshtastic_LocalModuleConfig_init_zero;
    owner = meshtastic_User_init_zero;
    myNodeInfo = meshtastic_MyNodeInfo_init_zero;
    myNodeInfo.my_node_num = kSource;
    testNodeDB->clearTestNodes();
    config.lora.region = meshtastic_Config_LoRaConfig_RegionCode_US;
    initRegion();
    channels.initDefaults();
    channels.onConfigChanged();
    preparePkiFixture();
    testModule = new BenchmarkModuleShim();
    Time::setTestMillis(0);
}
} // namespace

void test_control_round_trip_preserves_run_identity()
{
    auto original = runConfig();
    uint8_t wire[W12BenchmarkModule::CONTROL_BYTES] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::CONTROL_BYTES,
                           W12BenchmarkModule::encodeControl(wire, sizeof(wire), W12BenchmarkModule::Op::START, original));

    W12BenchmarkModule::Op op;
    W12BenchmarkModule::RunConfig decoded;
    TEST_ASSERT_TRUE(W12BenchmarkModule::decodeControl(wire, sizeof(wire), op, decoded));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Op::START), static_cast<uint8_t>(op));
    TEST_ASSERT_EQUAL_UINT32(original.runId, decoded.runId);
    TEST_ASSERT_EQUAL_UINT32(original.source, decoded.source);
    TEST_ASSERT_EQUAL_UINT32(original.destination, decoded.destination);
    TEST_ASSERT_EQUAL_UINT32(original.count, decoded.count);
    TEST_ASSERT_EQUAL_UINT16(original.size, decoded.size);
    TEST_ASSERT_EQUAL_UINT32(original.durationMs, decoded.durationMs);
    TEST_ASSERT_EQUAL_UINT16(original.window, decoded.window);
}

void test_control_rejects_truncated_and_nonzero_reserved_bytes()
{
    auto original = runConfig();
    uint8_t wire[W12BenchmarkModule::CONTROL_BYTES] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::CONTROL_BYTES,
                           W12BenchmarkModule::encodeControl(wire, sizeof(wire), W12BenchmarkModule::Op::RESET, original));

    W12BenchmarkModule::Op op;
    W12BenchmarkModule::RunConfig decoded;
    TEST_ASSERT_FALSE(W12BenchmarkModule::decodeControl(wire, sizeof(wire) - 1, op, decoded));
    wire[31] = 1;
    TEST_ASSERT_FALSE(W12BenchmarkModule::decodeControl(wire, sizeof(wire), op, decoded));
}

void test_config_bounds_reject_unbounded_runs()
{
    auto original = runConfig();
    TEST_ASSERT_TRUE(W12BenchmarkModule::validConfig(original));
    original.count = W12BenchmarkModule::MAX_COUNT + 1;
    TEST_ASSERT_FALSE(W12BenchmarkModule::validConfig(original));
    original = runConfig();
    original.durationMs = 0;
    TEST_ASSERT_FALSE(W12BenchmarkModule::validConfig(original));
    original = runConfig();
    original.size = W12BenchmarkModule::MAX_SIZE + 1;
    TEST_ASSERT_FALSE(W12BenchmarkModule::validConfig(original));
    original = runConfig();
    original.flags = 1;
    TEST_ASSERT_FALSE(W12BenchmarkModule::validConfig(original));
}

void test_data_round_trip_keeps_exact_219_byte_shape_and_pattern()
{
    auto original = runConfig();
    uint8_t wire[W12BenchmarkModule::DEFAULT_SIZE] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::DEFAULT_SIZE, W12BenchmarkModule::encodeData(wire, sizeof(wire), original, 37));
    TEST_ASSERT_EQUAL_UINT16(W12BenchmarkModule::DEFAULT_SIZE, sizeof(wire));

    W12BenchmarkModule::RunConfig decoded;
    uint32_t sequence = 0;
    TEST_ASSERT_TRUE(W12BenchmarkModule::decodeData(wire, sizeof(wire), decoded, sequence));
    TEST_ASSERT_EQUAL_UINT32(37, sequence);
    TEST_ASSERT_EQUAL_UINT32(original.runId, decoded.runId);
    TEST_ASSERT_EQUAL_UINT32(original.source, decoded.source);
    TEST_ASSERT_EQUAL_UINT32(original.destination, decoded.destination);
    TEST_ASSERT_EQUAL_UINT16(original.size, decoded.size);

    wire[W12BenchmarkModule::DATA_HEADER_BYTES + 7] ^= 0x80;
    uint8_t expected[W12BenchmarkModule::DEFAULT_SIZE] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::DEFAULT_SIZE,
                           W12BenchmarkModule::encodeData(expected, sizeof(expected), original, 37));
    TEST_ASSERT_NOT_EQUAL(wire[W12BenchmarkModule::DATA_HEADER_BYTES + 7], expected[W12BenchmarkModule::DATA_HEADER_BYTES + 7]);
}

void test_data_rejects_size_mismatch()
{
    auto original = runConfig();
    uint8_t wire[W12BenchmarkModule::DEFAULT_SIZE] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::DEFAULT_SIZE, W12BenchmarkModule::encodeData(wire, sizeof(wire), original, 0));
    wire[20] = static_cast<uint8_t>(W12BenchmarkModule::DEFAULT_SIZE - 1);
    wire[21] = static_cast<uint8_t>((W12BenchmarkModule::DEFAULT_SIZE - 1) >> 8);
    W12BenchmarkModule::RunConfig decoded;
    uint32_t sequence = 0;
    TEST_ASSERT_FALSE(W12BenchmarkModule::decodeData(wire, sizeof(wire), decoded, sequence));
}

void test_data_decode_keeps_out_of_range_sequence_visible_to_admission()
{
    auto original = runConfig();
    uint8_t wire[W12BenchmarkModule::DEFAULT_SIZE] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::DEFAULT_SIZE,
                           W12BenchmarkModule::encodeData(wire, sizeof(wire), original, original.count));

    W12BenchmarkModule::RunConfig decoded;
    uint32_t sequence = 0;
    TEST_ASSERT_TRUE(W12BenchmarkModule::decodeData(wire, sizeof(wire), decoded, sequence));
    TEST_ASSERT_EQUAL_UINT32(original.count, sequence);
    // The module's receiver admission owns the count bound so it can report out_of_range.
    TEST_ASSERT_TRUE(sequence >= original.count);
}

void test_report_has_fixed_offsets_for_all_diagnostic_counters()
{
    W12BenchmarkModule::Stats stats;
    stats.config = runConfig();
    stats.enqueued = 101;
    stats.sendFailures = 2;
    stats.txStarted = 100;
    stats.txSucceeded = 98;
    stats.txFailures = 1;
    stats.txDropped = 1;
    stats.txCancelled = 0;
    stats.received = 99;
    stats.missing = 901;
    stats.duplicates = 3;
    stats.corrupt = 4;
    stats.outOfRange = 5;
    stats.elapsedMs = 60000;
    stats.goodputBps = 28900;
    stats.prepared = true;
    stats.complete = true;

    uint8_t wire[W12BenchmarkModule::REPORT_BYTES] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::REPORT_BYTES, W12BenchmarkModule::encodeReport(wire, sizeof(wire), stats));
    TEST_ASSERT_EQUAL_HEX16(W12BenchmarkModule::MAGIC, static_cast<uint16_t>(wire[0] | wire[1] << 8));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::REPORT), wire[3]);
    TEST_ASSERT_EQUAL_UINT32(stats.enqueued, static_cast<uint32_t>(wire[30] | wire[31] << 8 | wire[32] << 16 | wire[33] << 24));
    TEST_ASSERT_EQUAL_UINT32(stats.txSucceeded,
                             static_cast<uint32_t>(wire[42] | wire[43] << 8 | wire[44] << 16 | wire[45] << 24));
    TEST_ASSERT_EQUAL_UINT32(stats.received, static_cast<uint32_t>(wire[58] | wire[59] << 8 | wire[60] << 16 | wire[61] << 24));
    TEST_ASSERT_EQUAL_UINT32(stats.goodputBps, static_cast<uint32_t>(wire[82] | wire[83] << 8 | wire[84] << 16 | wire[85] << 24));
}

void test_diagnostic_snapshot_is_local_asof_and_keeps_existing_wire_formats()
{
    auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(1, testRadio->pendingCount());

    testModule->onTxDelayScheduled(testRadio->pendingAt(0), true);
    testModule->onTxDelayScheduled(testRadio->pendingAt(0), false);
    testModule->onTxDelayFired(testRadio->pendingAt(0));
    testModule->onPreCanSendDeferred(testRadio->pendingAt(0));
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::ENERGY_BUSY);
    testModule->onCcaRssiSample(-90);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::FREE);
    testModule->onCcaRssiSample(-100);
    testModule->onRxIrq(true, true, false, false, false, false, false);
    testModule->onRxRead(true);
    testModule->onRxQueueEnqueued();
    testModule->onRxDecode(W12BenchmarkModule::RxDecodeResult::Success);
    testModule->onRxAuthenticated();
    testModule->onModuleReceiveHandlerDuration(3);

    auto wrongRun = run;
    wrongRun.runId++;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(wrongRun, W12BenchmarkModule::Op::SNAPSHOT_DIAGNOSTICS, run.source)));
    TEST_ASSERT_NULL(testModule->allocReply());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_DIAGNOSTICS, run.source,
                                                       meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA, run.source)));
    TEST_ASSERT_NULL(testModule->allocReply());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_DIAGNOSTICS, run.source)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::DIAGNOSTIC_REPORT_BYTES, reply->decoded.payload.size);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::DIAGNOSTICS), reply->decoded.payload.bytes[3]);
    TEST_ASSERT_EQUAL_UINT8(1 | 2 | 8 | 16 | 32, reply->decoded.payload.bytes[20]);
    TEST_ASSERT_EQUAL_UINT8(1, reply->decoded.payload.bytes[21]);
    TEST_ASSERT_EQUAL_UINT32(2, read32(reply->decoded.payload.bytes, 24));
    TEST_ASSERT_EQUAL_UINT32(1, read32(reply->decoded.payload.bytes, 28));
    TEST_ASSERT_EQUAL_UINT32(1, read32(reply->decoded.payload.bytes, 56));
    TEST_ASSERT_EQUAL_UINT32(1, read32(reply->decoded.payload.bytes, 220));
    TEST_ASSERT_EQUAL_UINT32(1, read32(reply->decoded.payload.bytes, 224));
    TEST_ASSERT_EQUAL_UINT32(1, read32(reply->decoded.payload.bytes, 228));
    packetPool.release(reply);

    testRadio->finishAt(0, RadioInterface::TxState::Sent);
    TEST_ASSERT_EQUAL_UINT(0, testRadio->pendingCount());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_DIAGNOSTICS, run.source)));
    reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT8(1 | 2 | 8 | 32, reply->decoded.payload.bytes[20]);
    TEST_ASSERT_EQUAL_UINT8(0, reply->decoded.payload.bytes[21]);
    packetPool.release(reply);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    const auto diagnostics = testModule->getDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.txDelayScheduledAttempts);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.ccaDecisions);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.rxReadSuccess);
    TEST_ASSERT_EQUAL_INT16(127, diagnostics.ccaRssiMinDbm);
    TEST_ASSERT_EQUAL_INT16(-127, diagnostics.ccaRssiMaxDbm);
}

void test_diagnostic_cca_events_are_aggregated_once_and_timing_uses_existing_slots()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(1, testRadio->pendingCount());
    const auto *packet = testRadio->pendingAt(0);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::NOT_READY);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::RSSI_READ_ERROR);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::RX_IRQ_PENDING);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::RX_ACTIVE);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::RSSI_INVALID);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::ENERGY_BUSY);
    testModule->onCcaDecision(W12BenchmarkModule::CcaReason::FREE);
    testModule->onCcaRssiSample(-121);
    testModule->onCcaRssiSample(-115);
    testModule->onCcaRssiSample(-105);
    testModule->onCcaRssiSample(-97);
    testModule->onCcaRssiSample(-92);
    testModule->onCcaRssiSample(-87);
    testModule->onCcaRssiSample(-82);
    testModule->onCcaRssiSample(-70);
    Time::advanceTestMillis(7);
    testModule->onTxFinished(packet, RadioInterface::TxState::Sent);
    const auto diagnostics = testModule->getDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(7, diagnostics.ccaDecisions);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.ccaReasons[0]);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.ccaReasons[6]);
    TEST_ASSERT_EQUAL_UINT32(8, diagnostics.ccaRssiSampleCount);
    TEST_ASSERT_EQUAL_INT16(-121, diagnostics.ccaRssiMinDbm);
    TEST_ASSERT_EQUAL_INT16(-70, diagnostics.ccaRssiMaxDbm);
    for (auto count : diagnostics.ccaRssiHistogram)
        TEST_ASSERT_EQUAL_UINT32(1, count);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txDurationCount);
    TEST_ASSERT_EQUAL_UINT32(7, diagnostics.txDurationSumMs);
    TEST_ASSERT_EQUAL_UINT32(7, diagnostics.txDurationMaxMs);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTerminal);
    testRadio->releaseAt(0);
}

void test_diagnostic_snapshot_accepts_zero_first_receiver_window()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.destination;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_DIAGNOSTICS, run.destination)));

    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT8(1 | 2 | 32, reply->decoded.payload.bytes[20]);
    TEST_ASSERT_EQUAL_UINT8(0, reply->decoded.payload.bytes[21]);
    TEST_ASSERT_EQUAL_UINT32(0, read32(reply->decoded.payload.bytes, 16));
    packetPool.release(reply);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
}

void test_radio_diagnostic_page_tracks_authorization_stages_buckets_and_reset()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.destination;
    Time::setTestMillis(1000);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.destination)));

    TEST_ASSERT_EQUAL_INT(
        static_cast<int>(ProcessMessage::STOP),
        static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_DIAGNOSTICS, run.destination)));
    meshtastic_MeshPacket *initialReply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(initialReply);
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, read32(initialReply->decoded.payload.bytes, 204));
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, read32(initialReply->decoded.payload.bytes, 208));
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, read32(initialReply->decoded.payload.bytes, 212));
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, read32(initialReply->decoded.payload.bytes, 220));
    packetPool.release(initialReply);

    W12BenchmarkModule::RadioDiagnostics signedDiagnostics;
    signedDiagnostics.rxStandbyLastResult = -7;
    W12BenchmarkModule::Stats signedStats;
    signedStats.config = run;
    uint8_t signedWire[W12BenchmarkModule::RADIO_DIAGNOSTIC_REPORT_BYTES] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RADIO_DIAGNOSTIC_REPORT_BYTES,
                           W12BenchmarkModule::encodeRadioDiagnosticsReport(signedWire, sizeof(signedWire), signedStats,
                                                                            signedDiagnostics, 0, 0, 0));
    TEST_ASSERT_EQUAL_INT16(-7, read16s(signedWire, 44));

    auto wrongRun = run;
    wrongRun.runId++;
    TEST_ASSERT_EQUAL_INT(
        static_cast<int>(ProcessMessage::CONTINUE),
        static_cast<int>(sendControl(wrongRun, W12BenchmarkModule::Op::SNAPSHOT_RADIO_DIAGNOSTICS, run.destination)));
    TEST_ASSERT_NULL(testModule->allocReply());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_DIAGNOSTICS, run.destination,
                                                       meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA, run.source)));

    testModule->onRxArmAttempt();
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::STANDBY, -7);
    testModule->onRxArmFinished(-7, W12BenchmarkModule::RxArmStage::STANDBY);
    testModule->onRxArmAttempt();
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::STANDBY, 0);
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::RX_START, -8);
    testModule->onRxArmFinished(-8, W12BenchmarkModule::RxArmStage::RX_START);
    testModule->onRxArmAttempt();
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::STANDBY, 0);
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::RX_START, 0);
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::IRQ_MAP, -9);
    testModule->onRxArmFinished(-9, W12BenchmarkModule::RxArmStage::IRQ_MAP);
    testModule->onRxArmAttempt();
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::STANDBY, 0);
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::RX_START, 0);
    testModule->onRxArmStage(W12BenchmarkModule::RxArmStage::IRQ_MAP, 0);
    testModule->onRxArmFinished(0, W12BenchmarkModule::RxArmStage::NONE);
    testModule->onRadioPhase(W12BenchmarkModule::RadioPhase::RX_START, 11);
    testModule->onRadioPhase(W12BenchmarkModule::RadioPhase::CHANNEL_ACTIVE, 22);
    testModule->onRadioPhase(W12BenchmarkModule::RadioPhase::START_SEND, 33);
    testModule->onRadioPoll();
    testModule->onRadioPollRx(0, 0x01020304, true, 0x0404);
    testModule->onRadioPollRx(-8, 0, false);
    testModule->onRadioPollRx(0, 0x00000001, false, 0x0402);
    testModule->onRadioPollTx(false);
    testModule->onRadioPollTx(true);

    testModule->onRxIrq(true, true, false, false, false, false, false);
    Time::setTestMillis(6000);
    testModule->onRxIrq(true, true, false, false, false, false, false);
    testModule->onRxRead(true);
    testModule->onRxAuthenticated();
    Time::setTestMillis(7000);

    TEST_ASSERT_EQUAL_INT(
        static_cast<int>(ProcessMessage::STOP),
        static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_DIAGNOSTICS, run.destination)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    const uint8_t *wire = reply->decoded.payload.bytes;
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RADIO_DIAGNOSTIC_REPORT_BYTES, reply->decoded.payload.size);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::RADIO_DIAGNOSTICS), wire[3]);
    TEST_ASSERT_EQUAL_UINT8(1 | 2 | 32, wire[20]);
    TEST_ASSERT_EQUAL_UINT8(0, wire[21]);
    TEST_ASSERT_EQUAL_UINT32(4, read32(wire, 24));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 28));
    TEST_ASSERT_EQUAL_UINT32(3, read32(wire, 32));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 40));
    TEST_ASSERT_EQUAL_INT16(0, read16s(wire, 44));
    TEST_ASSERT_EQUAL_UINT32(3, read32(wire, 46));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 50));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 64));
    TEST_ASSERT_EQUAL_UINT32(2, read32(wire, 60));
    TEST_ASSERT_EQUAL_UINT32(11, read32(wire, 76));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 108));
    TEST_ASSERT_EQUAL_UINT32(3, read32(wire, 112));
    TEST_ASSERT_EQUAL_UINT32(2, read32(wire, 116));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 120));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 124));
    TEST_ASSERT_EQUAL_UINT32(0x01020305, read32(wire, 134));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 156));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 160));
    TEST_ASSERT_EQUAL_UINT32(1000, read32(wire, 204));
    TEST_ASSERT_EQUAL_UINT32(1000, read32(wire, 208));
    TEST_ASSERT_EQUAL_UINT32(1000, read32(wire, 212));
    TEST_ASSERT_EQUAL_UINT8(0, wire[147]);
    TEST_ASSERT_EQUAL_UINT8(255, wire[151]);
    TEST_ASSERT_EQUAL_UINT8(4, wire[217]);
    TEST_ASSERT_EQUAL_UINT8(2, wire[218]);
    TEST_ASSERT_EQUAL_UINT8(1, wire[219]);
    TEST_ASSERT_EQUAL_UINT32(6000, read32(wire, 220));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 224));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 228));
    packetPool.release(reply);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    const auto radioDiagnostics = testModule->getRadioDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(0, radioDiagnostics.rxArmAttempts);
    TEST_ASSERT_EQUAL_UINT8(255, radioDiagnostics.rxArmLastStage);
    TEST_ASSERT_EQUAL_UINT8(255, radioDiagnostics.pollTxLastDone);
}

void test_behavior_control_is_local_authorized_and_reset_is_not_mid_run()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    TEST_ASSERT_FALSE(testModule->getStats().prepared);

    TEST_ASSERT_EQUAL_INT(
        static_cast<int>(ProcessMessage::CONTINUE),
        static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source,
                                     meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA, run.destination)));
    TEST_ASSERT_FALSE(testModule->getStats().prepared);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source,
                                                       meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT)));
    TEST_ASSERT_FALSE(testModule->getStats().prepared);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_TRUE(testModule->getStats().prepared);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));

    auto wrongRun = run;
    wrongRun.runId++;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(wrongRun, W12BenchmarkModule::Op::STOP, run.source)));
    TEST_ASSERT_TRUE(testModule->getStats().running);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(wrongRun, W12BenchmarkModule::Op::SNAPSHOT, run.source)));
    TEST_ASSERT_NULL(testModule->allocReply());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_TRUE(testModule->getStats().running);
}

#if W12_BENCHMARK_HAL_TIMING_ENABLED
void test_spi_yield_control_lifecycle_freezes_at_owned_terminal_boundary()
{
    const auto run = runConfig();
    BenchmarkDiagnosticRadio diagnosticRadio;

    // Op12 is local and exact-config gated. It cannot arm an unprepared run, and a foreign
    // configuration must not consume the request.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::ENABLE_SPI_YIELD, run.source)));
    constexpr NodeNum observer = 0x33333333;
    myNodeInfo.my_node_num = observer;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, observer)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::ENABLE_SPI_YIELD, observer)));
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    auto foreign = run;
    ++foreign.runId;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(foreign, W12BenchmarkModule::Op::ENABLE_SPI_YIELD, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::ENABLE_SPI_YIELD, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::ENABLE_SPI_YIELD, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));

    // A source run has a valid timing window. STOP marks it complete, but the report stays
    // unavailable while the owner's terminal callback is still pending.
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(1, testRadio->pendingCount());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    TEST_ASSERT_FALSE(testModule->getStats().running);
    TEST_ASSERT_TRUE(testModule->getStats().complete);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_SPI_YIELD, run.source)));

    testRadio->finishAt(0, RadioInterface::TxState::Cancelled);
    TEST_ASSERT_EQUAL_UINT(0, testRadio->pendingCount());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_SPI_YIELD, run.source)));
    auto *sourceReply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(sourceReply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::SPI_YIELD_REPORT_BYTES, sourceReply->decoded.payload.size);
    const uint8_t *sourceWire = sourceReply->decoded.payload.bytes;
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::SPI_YIELD), sourceWire[3]);
    TEST_ASSERT_EQUAL_UINT8(1 | 4 | 8, sourceWire[20]);
    TEST_ASSERT_EQUAL_UINT8(0, sourceWire[21]);
    TEST_ASSERT_EQUAL_UINT32(0, read32(sourceWire, 24));
    TEST_ASSERT_EQUAL_UINT32(0, read32(sourceWire, 28));
    TEST_ASSERT_EQUAL_UINT32(0, read32(sourceWire, 32));
    TEST_ASSERT_EQUAL_UINT32(0, read32(sourceWire, 40));
    TEST_ASSERT_EQUAL_UINT8(1, sourceWire[68]);
    TEST_ASSERT_EQUAL_UINT8(0, sourceWire[69]);
    for (size_t offset = 70; offset < W12BenchmarkModule::SPI_YIELD_REPORT_BYTES; ++offset)
        TEST_ASSERT_EQUAL_UINT8(0, sourceWire[offset]);
    packetPool.release(sourceReply);

    // RESET clears the nonpersistent arm and counters. A snapshot from the new prepared run is
    // rejected until ENABLE and a complete valid window happen again.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_SPI_YIELD, run.source)));

    // A receiver with no authenticated frame has no timing window, even when its deadline is
    // reached, so the completed collector still cannot produce Op11.
    myNodeInfo.my_node_num = run.destination;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::ENABLE_SPI_YIELD, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.destination)));
    Time::setTestMillis(run.durationMs);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_SPI_YIELD, run.destination)));
    TEST_ASSERT_NULL(testModule->allocReply());

    // Once an authenticated frame opens the receiver window, deadline completion is a valid
    // terminal run and the frozen page becomes available.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::ENABLE_SPI_YIELD, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(testModule->handleReceived(makeData(run, 0))));
    Time::setTestMillis(run.durationMs);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(testModule->handleReceived(makeData(run, 1))));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_SPI_YIELD, run.destination)));
    auto *receiverReply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(receiverReply);
    TEST_ASSERT_EQUAL_UINT8(1 | 4 | 8, receiverReply->decoded.payload.bytes[20]);
    TEST_ASSERT_EQUAL_UINT8(1, receiverReply->decoded.payload.bytes[68]);
    packetPool.release(receiverReply);
}
#endif

void test_radio_diagnostic_tail_keeps_rx_done_after_completion_with_pending_tx()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    Time::setTestMillis(0);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(1, testRadio->pendingCount());

    testModule->onRxIrq(true, true, false, false, false, false, false);
    Time::setTestMillis(5);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    testModule->onRxIrq(true, true, false, false, false, false, false);
    TEST_ASSERT_EQUAL_UINT32(1, testModule->getDiagnostics().rxIrqDone);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_DIAGNOSTICS, run.source)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    const uint8_t *wire = reply->decoded.payload.bytes;
    TEST_ASSERT_EQUAL_UINT8(1 | 4 | 16 | 32, wire[20]);
    TEST_ASSERT_EQUAL_UINT8(1, wire[21]);
    TEST_ASSERT_EQUAL_UINT32(2, read32(wire, 156));
    TEST_ASSERT_EQUAL_UINT32(0, read32(wire, 204));
    packetPool.release(reply);

    testRadio->finishAt(0, RadioInterface::TxState::Sent);
    TEST_ASSERT_EQUAL_UINT(static_cast<unsigned>(0), testRadio->pendingCount());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
}

void test_rx_liveness_page_is_fixed_wire_and_local_authorized()
{
    const auto run = runConfig();
    W12BenchmarkModule::Stats stats;
    stats.config = run;
    stats.prepared = true;
    stats.running = true;
    stats.elapsedMs = 77;
    W12BenchmarkModule::RxLivenessDiagnostics diagnostics;
    diagnostics.snapshotSequence = 9;
    diagnostics.snapshotTimeMs = 1234;
    diagnostics.sampleStatus = 1 | 2 | 4 | 32;
    diagnostics.sampleSource = 1;
    diagnostics.rearmCount = 1;
    diagnostics.rearmResult = static_cast<uint8_t>(W12BenchmarkModule::RxLivenessRearmResult::SOFTWARE_ARMED);
    diagnostics.rearmBeforeState = 0x14;
    diagnostics.rearmAfterState = 0x15;
    diagnostics.rearmLastTimeMs = 1200;
    diagnostics.rearmLastDurationUs = 33;
    diagnostics.rawIrqFlags = 0x10203040;
    diagnostics.rawStatus = 0x0404;
    diagnostics.irqReadResult = -7;
    diagnostics.chipRxPackets = 12;
    diagnostics.chipCrcErrors = 3;
    diagnostics.chipLenErrors = 4;
    diagnostics.chipStatsResult = 0;
    diagnostics.rssiDbm = -91;
    diagnostics.rssiReadResult = 0;
    diagnostics.softwareState = 0x15;

    uint8_t wire[W12BenchmarkModule::RX_LIVENESS_REPORT_BYTES] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RX_LIVENESS_REPORT_BYTES,
                           W12BenchmarkModule::encodeRxLivenessReport(wire, sizeof(wire), stats, diagnostics, 2));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::RX_LIVENESS), wire[3]);
    TEST_ASSERT_EQUAL_UINT8(1 | 2 | 16 | 32, wire[20]);
    TEST_ASSERT_EQUAL_UINT8(2, wire[21]);
    TEST_ASSERT_EQUAL_UINT32(9, read32(wire, 24));
    TEST_ASSERT_EQUAL_UINT32(1234, read32(wire, 28));
    TEST_ASSERT_EQUAL_UINT8(1 | 2 | 4 | 32, wire[32]);
    TEST_ASSERT_EQUAL_UINT8(1, wire[33]);
    TEST_ASSERT_EQUAL_UINT32(0x10203040, read32(wire, 52));
    TEST_ASSERT_EQUAL_UINT16(0x0404, static_cast<uint16_t>(wire[56] | wire[57] << 8));
    TEST_ASSERT_EQUAL_INT16(-7, read16s(wire, 58));
    TEST_ASSERT_EQUAL_INT16(-91, read16s(wire, 68));
    TEST_ASSERT_EQUAL_INT16(0, read16s(wire, 70));
    TEST_ASSERT_EQUAL_UINT32(0x15, read32(wire, 72));

    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    Time::setTestMillis(41);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS, run.source)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RX_LIVENESS_REPORT_BYTES, reply->decoded.payload.size);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::RX_LIVENESS), reply->decoded.payload.bytes[3]);
    TEST_ASSERT_EQUAL_UINT8(1 | 2 | 32, reply->decoded.payload.bytes[20]);
    TEST_ASSERT_EQUAL_UINT32(41, read32(reply->decoded.payload.bytes, 28));
    TEST_ASSERT_EQUAL_UINT8(0, reply->decoded.payload.bytes[32]);
    TEST_ASSERT_EQUAL_INT16(INT16_MIN, read16s(reply->decoded.payload.bytes, 58));
    packetPool.release(reply);

    auto wrongRun = run;
    wrongRun.runId++;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(wrongRun, W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS, run.source)));
    TEST_ASSERT_NULL(testModule->allocReply());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RX_LIVENESS, run.source,
                                                       meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL, run.source)));
    TEST_ASSERT_NULL(testModule->allocReply());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
}

void test_rx_liveness_rearm_requires_receiver_window_and_radio_and_does_not_consume_budget()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.destination;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.destination)));

    // Before the first authenticated frame there is no current receiver window.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination)));
    TEST_ASSERT_NULL(testModule->allocReply());

    Time::setTestMillis(100);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(testModule->handleReceived(makeData(run, 0))));
    TEST_ASSERT_EQUAL_UINT(1, testModule->getStats().received);

    // The native benchmark fixture has no RadioLib instance. The operation must reject without
    // consuming its one-shot budget or manufacturing a report.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination)));
    TEST_ASSERT_NULL(testModule->allocReply());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination)));
    TEST_ASSERT_NULL(testModule->allocReply());

    BenchmarkDiagnosticRadio diagnosticRadio;
    diagnosticRadio.sending = true;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination)));
    TEST_ASSERT_EQUAL_UINT32(0, diagnosticRadio.startReceiveCalls);
    diagnosticRadio.sending = false;
    diagnosticRadio.scriptedSample.irqReadResult = -8;
    diagnosticRadio.scriptedSample.chipStatsResult = -7;
    diagnosticRadio.scriptedSample.rssiReadResult = -9;
    diagnosticRadio.scriptedSample.softwareState = 0x15;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination)));
    TEST_ASSERT_EQUAL_UINT32(1, diagnosticRadio.startReceiveCalls);
    meshtastic_MeshPacket *rearmReply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(rearmReply);
    const uint8_t *rearmWire = rearmReply->decoded.payload.bytes;
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RX_LIVENESS_REPORT_BYTES, rearmReply->decoded.payload.size);
    TEST_ASSERT_EQUAL_UINT8(8 | 32, rearmWire[32]);
    TEST_ASSERT_EQUAL_UINT32(1, read32(rearmWire, 34));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::RxLivenessRearmResult::SOFTWARE_NOT_ARMED), rearmWire[38]);
    TEST_ASSERT_EQUAL_INT16(-8, read16s(rearmWire, 58));
    TEST_ASSERT_EQUAL_INT16(-7, read16s(rearmWire, 66));
    TEST_ASSERT_EQUAL_INT16(-9, read16s(rearmWire, 70));
    packetPool.release(rearmReply);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination)));
    TEST_ASSERT_EQUAL_UINT32(1, diagnosticRadio.startReceiveCalls);
    TEST_ASSERT_NULL(testModule->allocReply());

    auto wrongRun = run;
    wrongRun.runId++;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(wrongRun, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::REARM_RX_LIVENESS, run.destination,
                                                       meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL, run.source)));

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
}

void test_behavior_producer_uses_real_service_and_terminal_slots()
{
    auto run = runConfig();
    run.window = 2;
    myNodeInfo.my_node_num = run.source;

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));

    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(2, testRadio->pendingCount());
    TEST_ASSERT_EQUAL_UINT(2, testModule->getStats().enqueued);
    TEST_ASSERT_EQUAL_UINT(2, testModule->getStats().txStarted);
    const meshtastic_MeshPacket *first = testRadio->pendingAt(0);
    TEST_ASSERT_TRUE(first->pki_encrypted);
    TEST_ASSERT_FALSE(first->want_ack);
    TEST_ASSERT_EQUAL_UINT8(0, first->hop_limit);
    TEST_ASSERT_EQUAL_UINT(meshtastic_MeshPacket_encrypted_tag, first->which_payload_variant);
    TEST_ASSERT_TRUE(first->encrypted.size <= MAX_RADIO_PAYLOAD_LEN);

    // The physical window blocks a third candidate until a terminal callback frees a slot.
    TEST_ASSERT_EQUAL_INT(5, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(2, testModule->getStats().enqueued);
    TEST_ASSERT_EQUAL_UINT32(1, testModule->getDiagnostics().producerBlockedTotal);
    TEST_ASSERT_EQUAL_UINT32(1, testModule->getDiagnostics().producerQueueWindow);

    // A duplicate start callback is harmless, and an unrelated packet cannot affect counters.
    testModule->onTxStarted(first);
    meshtastic_MeshPacket unrelated = meshtastic_MeshPacket_init_zero;
    unrelated.id = 0x7a7a7a7a;
    testModule->onTxStarted(&unrelated);
    testModule->onTxFinished(&unrelated, RadioInterface::TxState::Sent);
    TEST_ASSERT_EQUAL_UINT(2, testModule->getStats().txStarted);
    TEST_ASSERT_EQUAL_UINT(0, testModule->getStats().txSucceeded);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));

    testRadio->callbackAt(0, RadioInterface::TxState::Sent);
    testRadio->callbackAt(0, RadioInterface::TxState::Sent);
    testRadio->releaseAt(0);
    TEST_ASSERT_EQUAL_UINT(1, testModule->getStats().txSucceeded);
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(3, testModule->getStats().enqueued);

    testRadio->callbackAt(0, RadioInterface::TxState::Failed);
    testRadio->releaseAt(0);
    testRadio->callbackAt(0, RadioInterface::TxState::Dropped);
    testRadio->releaseAt(0);
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(4, testModule->getStats().enqueued);
    testRadio->callbackAt(0, RadioInterface::TxState::Cancelled);
    testRadio->releaseAt(0);

    const auto stats = testModule->getStats();
    TEST_ASSERT_EQUAL_UINT(4, stats.txStarted);
    TEST_ASSERT_EQUAL_UINT(1, stats.txSucceeded);
    TEST_ASSERT_EQUAL_UINT(1, stats.txFailures);
    TEST_ASSERT_EQUAL_UINT(1, stats.txDropped);
    TEST_ASSERT_EQUAL_UINT(1, stats.txCancelled);
    TEST_ASSERT_EQUAL_UINT(0, testRadio->pendingCount());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
}

void test_behavior_receiver_requires_direct_authenticated_rf_and_validates_pattern()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.destination;

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.destination)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.destination)));

    auto notPki = makeData(run, 0, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA, false);
    testModule->handleReceived(notPki);
    auto mqtt = makeData(run, 0, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA, true, true);
    testModule->handleReceived(mqtt);
    auto local = makeData(run, 0, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL, true);
    testModule->handleReceived(local);
    TEST_ASSERT_EQUAL_UINT(0, testModule->getStats().received);
    TEST_ASSERT_EQUAL_UINT(0, testModule->getStats().elapsedMs);

    Time::setTestMillis(100);
    auto first = makeData(run, 0);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE), static_cast<int>(testModule->handleReceived(first)));
    TEST_ASSERT_EQUAL_UINT(1, testModule->getStats().received);

    auto corrupt = makeData(run, 1);
    corrupt.decoded.payload.bytes[W12BenchmarkModule::DATA_HEADER_BYTES + 2] ^= 0x40;
    testModule->handleReceived(corrupt);
    TEST_ASSERT_EQUAL_UINT(1, testModule->getStats().corrupt);

    auto validAfterCorrupt = makeData(run, 1);
    testModule->handleReceived(validAfterCorrupt);
    testModule->handleReceived(validAfterCorrupt);
    TEST_ASSERT_EQUAL_UINT(2, testModule->getStats().received);
    TEST_ASSERT_EQUAL_UINT(1, testModule->getStats().duplicates);

    auto outOfRange = makeData(run, run.count);
    testModule->handleReceived(outOfRange);
    TEST_ASSERT_EQUAL_UINT(1, testModule->getStats().outOfRange);

    Time::advanceTestMillis(run.durationMs);
    auto late = makeData(run, 2);
    testModule->handleReceived(late);
    TEST_ASSERT_FALSE(testModule->getStats().running);
    TEST_ASSERT_TRUE(testModule->getStats().complete);
    TEST_ASSERT_EQUAL_UINT(2, testModule->getStats().received);
    TEST_ASSERT_EQUAL_UINT(run.durationMs, testModule->getStats().elapsedMs);
}

void test_behavior_mesh_service_rejects_matching_api_data_but_accepts_registered_owner_send()
{
    auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));

    meshtastic_MeshPacket *apiData =
        packetPool.allocCopy(makeData(run, 0, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_API, true));
    TEST_ASSERT_NOT_NULL(apiData);
    apiData->from = 0;
    const ErrorCode rejected = testService->sendToMesh(apiData, RX_SRC_USER, false);
    TEST_ASSERT_NOT_EQUAL(ERRNO_OK, rejected);
    TEST_ASSERT_EQUAL_UINT(0, testModule->getStats().enqueued);
    TEST_ASSERT_EQUAL_UINT(0, testRadio->pendingCount());

    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(1, testModule->getStats().enqueued);
    TEST_ASSERT_EQUAL_UINT(1, testRadio->pendingCount());
}

void test_pre_send_attribution_tracks_only_valid_timer_dispatches()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    const auto *packet = testRadio->pendingAt(0);

    // The due timestamp crosses the 32-bit clock wrap. The wrap-safe deadline helper records 3 ms late.
    Time::setTestMillis(UINT32_MAX - 1);
    testModule->onTxDelayScheduled(packet, true, 1);
    testModule->onTxDelayScheduled(packet, false, 7);
    Time::setTestMillis(4);
    testModule->onTxDelayNotification(true, packet);
    auto diagnostics = testModule->getPreSendAttributionDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerAccepted);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerDispatches);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerLateCount);
    TEST_ASSERT_EQUAL_UINT32(3, diagnostics.txTimerLateSumMs);
    TEST_ASSERT_EQUAL_UINT32(3, diagnostics.txTimerLateMaxMs);
    TEST_ASSERT_FALSE(diagnostics.txTimerActive);

    // A second accepted schedule overwrites the tracked slot. A null notification is stale and cannot be late.
    testModule->onTxDelayScheduled(packet, true, 10);
    testModule->onTxDelayScheduled(packet, true, 20);
    Time::setTestMillis(30);
    testModule->onTxDelayNotification(true, nullptr);
    diagnostics = testModule->getPreSendAttributionDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(3, diagnostics.txTimerAccepted);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerOverwritten);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerStale);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerLateCount);

    // Cancellation and IRQ displacement clear tracking without producing a late dispatch.
    testModule->onTxDelayScheduled(packet, true, 40);
    testModule->onTxFinished(packet, RadioInterface::TxState::Cancelled);
    diagnostics = testModule->getPreSendAttributionDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerCancelled);
    TEST_ASSERT_FALSE(diagnostics.txTimerActive);
    testRadio->releaseAt(0);

    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    const auto *nextPacket = testRadio->pendingAt(0);
    testModule->onTxDelayScheduled(nextPacket, true, 50);
    testModule->onTxDelayNotification(false, nextPacket);
    diagnostics = testModule->getPreSendAttributionDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txTimerIrqDisplaced);
    TEST_ASSERT_FALSE(diagnostics.txTimerActive);

    testModule->onPreCanSendDeferred(nextPacket, W12BenchmarkModule::PreSendBusyReason::BUSY_TX);
    testModule->onPreCanSendDeferred(nextPacket, W12BenchmarkModule::PreSendBusyReason::BUSY_RX_ACTIVE);
    testModule->onPreCanSendDeferred(nextPacket, W12BenchmarkModule::PreSendBusyReason::BUSY_RX_IRQ_READ_FAILURE);
    diagnostics = testModule->getPreSendAttributionDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.busyTxDeferrals);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.busyRxActiveDeferrals);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.busyRxIrqReadFailureDeferrals);
}

void test_pre_send_attribution_page_is_fixed_and_local_without_radio_sample()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_PRE_SEND_ATTRIBUTION, run.source)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::PRE_SEND_ATTRIBUTION_REPORT_BYTES, reply->decoded.payload.size);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::PRE_SEND_ATTRIBUTION),
                            reply->decoded.payload.bytes[3]);
    TEST_ASSERT_EQUAL_UINT8(0, reply->decoded.payload.bytes[73]);
    TEST_ASSERT_EQUAL_INT16(INT16_MIN, read16s(reply->decoded.payload.bytes, 98));
    packetPool.release(reply);
}

void test_phase_timing_extension_is_bounded_and_default_off()
{
    W12BenchmarkModule::Stats stats;
    stats.config = runConfig();
    stats.prepared = true;
    stats.complete = true;
    W12BenchmarkModule::PreSendAttributionDiagnostics diagnostics;
    diagnostics.phaseTiming.available = true;
    diagnostics.phaseTiming.producerSendToMeshUs = {3, 90, 40};
    diagnostics.phaseTiming.burstPrepareUs = {2, 12, 8};
    diagnostics.phaseTiming.burstGuardLateMs = {1, 4, 4};
    diagnostics.phaseTiming.rxGateDecodeUs = {4, 100, 30};
    diagnostics.phaseTiming.pkiCcmEncodeUs = {2, 90, 55};
    diagnostics.phaseTiming.pkiCcmDecodeUs = {3, 120, 50};
    diagnostics.phaseTiming.pkiCcmAvailable = true;
    diagnostics.phaseTiming.failedTxCount = 1;
    diagnostics.phaseTiming.failedTxLastPacketId = 0x1234;
    diagnostics.phaseTiming.failedTxLastSequence = 37;
    diagnostics.phaseTiming.failedTxLastAtMs = 99;
    diagnostics.phaseTiming.failedTxLastRadioResult = INT16_MIN;

    uint8_t wire[W12BenchmarkModule::PRE_SEND_ATTRIBUTION_REPORT_BYTES] = {};
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::PRE_SEND_ATTRIBUTION_REPORT_BYTES,
                           W12BenchmarkModule::encodePreSendAttributionReport(wire, sizeof(wire), stats, diagnostics, 0));
    TEST_ASSERT_EQUAL_UINT8(0, wire[232]);
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    TEST_ASSERT_EQUAL_UINT8(1, wire[178]);
    TEST_ASSERT_EQUAL_UINT32(3, read32(wire, 130));
    TEST_ASSERT_EQUAL_UINT32(90, read32(wire, 134));
    TEST_ASSERT_EQUAL_UINT32(40, read32(wire, 138));
    TEST_ASSERT_EQUAL_UINT32(2, read32(wire, 142));
    TEST_ASSERT_EQUAL_UINT32(12, read32(wire, 146));
    TEST_ASSERT_EQUAL_UINT32(8, read32(wire, 150));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 154));
    TEST_ASSERT_EQUAL_UINT32(4, read32(wire, 158));
    TEST_ASSERT_EQUAL_UINT32(4, read32(wire, 162));
    TEST_ASSERT_EQUAL_UINT32(4, read32(wire, 166));
    TEST_ASSERT_EQUAL_UINT32(100, read32(wire, 170));
    TEST_ASSERT_EQUAL_UINT32(30, read32(wire, 174));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 179));
    TEST_ASSERT_EQUAL_UINT32(0x1234, read32(wire, 183));
    TEST_ASSERT_EQUAL_UINT32(37, read32(wire, 187));
    TEST_ASSERT_EQUAL_UINT32(99, read32(wire, 191));
    TEST_ASSERT_EQUAL_UINT32(2, read32(wire, 198));
    TEST_ASSERT_EQUAL_UINT32(90, read32(wire, 202));
    TEST_ASSERT_EQUAL_UINT32(55, read32(wire, 206));
    TEST_ASSERT_EQUAL_UINT32(3, read32(wire, 210));
    TEST_ASSERT_EQUAL_UINT32(120, read32(wire, 214));
    TEST_ASSERT_EQUAL_UINT32(50, read32(wire, 218));
    TEST_ASSERT_EQUAL_UINT8(1, wire[222]);
    for (size_t offset = 223; offset < W12BenchmarkModule::PRE_SEND_ATTRIBUTION_REPORT_BYTES; offset++)
        TEST_ASSERT_EQUAL_UINT8(0, wire[offset]);
#else
    for (size_t offset = 130; offset <= 197; offset++)
        TEST_ASSERT_EQUAL_UINT8(0, wire[offset]);
    for (size_t offset = 198; offset < W12BenchmarkModule::PRE_SEND_ATTRIBUTION_REPORT_BYTES; offset++)
        TEST_ASSERT_EQUAL_UINT8(0, wire[offset]);
#endif
}

void test_phase_timing_aggregates_wrap_deadline_and_saturate()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));

    testModule->onProducerSendToMeshDuration(UINT32_MAX);
    testModule->onProducerSendToMeshDuration(1);
    testModule->onW12BurstPrepareDuration(3, true);
    testModule->onW12BurstPrepareDuration(5, false);
    // The due time is just before the uint32 millisecond clock wraps. Five milliseconds of
    // signed-deadline lateness must still be attributed to this live event.
    testModule->onW12BurstGuardLateness(2, UINT32_MAX - 2);
    testModule->onW12BurstGuardLateness(1, 2);
    const auto diagnostics = testModule->getPreSendAttributionDiagnostics();
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    TEST_ASSERT_TRUE(diagnostics.phaseTiming.available);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.phaseTiming.producerSendToMeshUs.count);
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, diagnostics.phaseTiming.producerSendToMeshUs.sum);
    TEST_ASSERT_EQUAL_UINT32(UINT32_MAX, diagnostics.phaseTiming.producerSendToMeshUs.max);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.phaseTiming.burstPrepareUs.count);
    TEST_ASSERT_EQUAL_UINT32(8, diagnostics.phaseTiming.burstPrepareUs.sum);
    TEST_ASSERT_EQUAL_UINT32(5, diagnostics.phaseTiming.burstPrepareUs.max);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.phaseTiming.burstPrepareSuccesses);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.phaseTiming.burstPrepareFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.phaseTiming.burstGuardLateMs.count);
    TEST_ASSERT_EQUAL_UINT32(5, diagnostics.phaseTiming.burstGuardLateMs.sum);
#else
    TEST_ASSERT_FALSE(diagnostics.phaseTiming.available);
#endif
}

void test_pki_ccm_timing_aggregates_retry_calls_without_a_second_gate_sample()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));

    testModule->onPkiCcmEncodeTiming(1, 12, 12);
    testModule->onPkiCcmDecodeTiming(2, 80, 50);
    testModule->onPkiCcmDecodeTiming(1, 20, 20);
    const auto diagnostics = testModule->getPreSendAttributionDiagnostics();
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    TEST_ASSERT_TRUE(diagnostics.phaseTiming.available);
    TEST_ASSERT_TRUE(diagnostics.phaseTiming.pkiCcmAvailable);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.phaseTiming.pkiCcmEncodeUs.count);
    TEST_ASSERT_EQUAL_UINT32(12, diagnostics.phaseTiming.pkiCcmEncodeUs.sum);
    TEST_ASSERT_EQUAL_UINT32(3, diagnostics.phaseTiming.pkiCcmDecodeUs.count);
    TEST_ASSERT_EQUAL_UINT32(100, diagnostics.phaseTiming.pkiCcmDecodeUs.sum);
    TEST_ASSERT_EQUAL_UINT32(50, diagnostics.phaseTiming.pkiCcmDecodeUs.max);
#else
    TEST_ASSERT_FALSE(diagnostics.phaseTiming.pkiCcmAvailable);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.phaseTiming.pkiCcmEncodeUs.count);
    TEST_ASSERT_EQUAL_UINT32(0, diagnostics.phaseTiming.pkiCcmDecodeUs.count);
#endif
}

#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
void test_radio_gaps_report_zero_and_overflow_encoding_is_strict()
{
    W12BenchmarkModule::Stats stats;
    stats.config = runConfig();
    stats.prepared = true;
    stats.complete = true;
    W12BenchmarkModule::RadioGapDiagnostics diagnostics;
    uint8_t wire[W12BenchmarkModule::RADIO_GAPS_REPORT_BYTES];
    memset(wire, 0xa5, sizeof(wire));
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RADIO_GAPS_REPORT_BYTES,
                           W12BenchmarkModule::encodeRadioGapsReport(wire, sizeof(wire), stats, diagnostics, 0));
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::OWNER_RADIO_GAPS), wire[3]);
    TEST_ASSERT_EQUAL_UINT8(1 | 4 | 8, wire[20]);
    TEST_ASSERT_EQUAL_UINT8(0, wire[21]);
    TEST_ASSERT_EQUAL_UINT8(1, wire[100]);
    TEST_ASSERT_EQUAL_UINT8(0, wire[101]);
    for (size_t offset = 24; offset < 100; offset++)
        TEST_ASSERT_EQUAL_UINT8(0, wire[offset]);
    for (size_t offset = 102; offset < sizeof(wire); offset++)
        TEST_ASSERT_EQUAL_UINT8(0, wire[offset]);

    diagnostics.ownerRxNotifyToRearmUs.count = 1;
    diagnostics.ownerRxNotifyToRearmUs.minUs = 7;
    diagnostics.ownerRxNotifyToRearmUs.maxUs = 9;
    diagnostics.ownerRxNotifyToRearmUs.sumUs = UINT64_MAX;
    diagnostics.overflow = true;
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RADIO_GAPS_REPORT_BYTES,
                           W12BenchmarkModule::encodeRadioGapsReport(wire, sizeof(wire), stats, diagnostics, 0));
    TEST_ASSERT_EQUAL_UINT32(1, read32(wire, 24));
    TEST_ASSERT_EQUAL_UINT32(7, read32(wire, 28));
    TEST_ASSERT_EQUAL_UINT32(9, read32(wire, 32));
    TEST_ASSERT_EQUAL_UINT8(1, wire[101]);
}

void test_radio_gaps_controls_gate_completed_page_and_pair_owner_hooks()
{
    auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::CONTINUE),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_GAPS, run.source)));
    TEST_ASSERT_NULL(testModule->allocReply());

    testModule->onOwnerRxNotification(100, 150, 0, 1, 0, 0, true);
    testModule->onOwnerRxNotification(200, 250, 1, 1, 0, 0, false);
    testModule->onOwnerRxNotification(300, 350, 1, 2, 0, 1, true);
    testModule->onOwnerTxNotification(400, true, true);
    testModule->onOwnerTxStartTransmitCall(475, true);
    testModule->onOwnerTxStartTransmitResult(true);
    testModule->onOwnerTxNotification(500, true, false);
    testModule->onOwnerTxNotification(600, true, true);
    testModule->onOwnerTxStartTransmitFailure(true);
    testModule->onOwnerTxNotification(700, true, true);

    auto diagnostics = testModule->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.ownerRxNotifyToRearmUs.count);
    TEST_ASSERT_EQUAL_UINT32(50, diagnostics.ownerRxNotifyToRearmUs.sumUs);
    TEST_ASSERT_EQUAL_UINT32(50, diagnostics.ownerRxNotifyToRearmUs.minUs);
    TEST_ASSERT_EQUAL_UINT32(50, diagnostics.ownerRxNotifyToRearmUs.maxUs);
    TEST_ASSERT_EQUAL_UINT32(3, diagnostics.rxNotifications);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.rxValidDone);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.rxInvalid);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.rxArmFailures);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.ownerTxNotifyToStartTransmitCallUs.count);
    TEST_ASSERT_EQUAL_UINT32(75, diagnostics.ownerTxNotifyToStartTransmitCallUs.minUs);
    TEST_ASSERT_EQUAL_UINT32(75, diagnostics.ownerTxNotifyToStartTransmitCallUs.maxUs);
    TEST_ASSERT_EQUAL_UINT32(75, diagnostics.ownerTxNotifyToStartTransmitCallUs.sumUs);
    // Each valid owner notification is a valid TX IRQ classification. The
    // sequence above intentionally exercises three such notifications.
    TEST_ASSERT_EQUAL_UINT32(3, diagnostics.txValidDone);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txInvalidIrq);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.txStartFailures);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    TEST_ASSERT_EQUAL_UINT32(1, testModule->getRadioGapDiagnostics().txUnpaired);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_GAPS, run.source)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT(W12BenchmarkModule::RADIO_GAPS_REPORT_BYTES, reply->decoded.payload.size);
    TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(W12BenchmarkModule::Kind::OWNER_RADIO_GAPS), reply->decoded.payload.bytes[3]);
    TEST_ASSERT_EQUAL_UINT8(1 | 4 | 8, reply->decoded.payload.bytes[20]);
    TEST_ASSERT_EQUAL_UINT8(0, reply->decoded.payload.bytes[21]);
    packetPool.release(reply);

    ++run.runId;
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::RESET, run.source)));
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::START, run.source)));
    testModule->onOwnerTxStartTransmitCall(1000, true);
    TEST_ASSERT_EQUAL_UINT32(0, testModule->getRadioGapDiagnostics().ownerTxNotifyToStartTransmitCallUs.count);
}

void test_radio_gaps_reject_intervals_outside_finite_run_window()
{
    auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    sendControl(run, W12BenchmarkModule::Op::RESET, run.source);
    sendControl(run, W12BenchmarkModule::Op::START, run.source);
    testModule->onOwnerRxNotification(0, W12BenchmarkModule::MAX_DURATION_MS * 1000UL + 1, 0, 1, 0, 0, true);
    testModule->onOwnerTxNotification(0, true, true);
    testModule->onOwnerTxStartTransmitCall(W12BenchmarkModule::MAX_DURATION_MS * 1000UL + 1, true);
    testModule->onOwnerRxNotification(UINT32_MAX - 10, 5, 1, 2, 0, 0, true);
    testModule->onOwnerTxNotification(UINT32_MAX - 10, true, true);
    testModule->onOwnerTxStartTransmitCall(5, true);
    testModule->onOwnerTxStartTransmitResult(true);
    const auto diagnostics = testModule->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.ownerRxNotifyToRearmUs.count);
    TEST_ASSERT_EQUAL_UINT32(16, diagnostics.ownerRxNotifyToRearmUs.sumUs);
    TEST_ASSERT_EQUAL_UINT32(16, diagnostics.ownerRxNotifyToRearmUs.minUs);
    TEST_ASSERT_EQUAL_UINT32(16, diagnostics.ownerRxNotifyToRearmUs.maxUs);
    TEST_ASSERT_EQUAL_UINT32(1, diagnostics.ownerTxNotifyToStartTransmitCallUs.count);
    TEST_ASSERT_EQUAL_UINT32(16, diagnostics.ownerTxNotifyToStartTransmitCallUs.sumUs);
    TEST_ASSERT_EQUAL_UINT32(16, diagnostics.ownerTxNotifyToStartTransmitCallUs.minUs);
    TEST_ASSERT_EQUAL_UINT32(16, diagnostics.ownerTxNotifyToStartTransmitCallUs.maxUs);
    TEST_ASSERT_EQUAL_UINT32(2, diagnostics.intervalRejected);
}

void test_radio_gaps_stop_pending_cancel_freezes_page()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    sendControl(run, W12BenchmarkModule::Op::RESET, run.source);
    sendControl(run, W12BenchmarkModule::Op::START, run.source);
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(1, testRadio->pendingCount());
    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    TEST_ASSERT_TRUE(testModule->getStats().complete);
    testRadio->finishAt(0, RadioInterface::TxState::Cancelled);
    TEST_ASSERT_EQUAL_UINT(0, testRadio->pendingCount());
    const auto frozen = testModule->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(0, frozen.txUnpaired);
    TEST_ASSERT_EQUAL_UINT32(0, frozen.txValidDone);

    testModule->onOwnerRxNotification(200, 250, 0, 1, 0, 0, true);
    testModule->onOwnerTxNotification(300, true, true);
    const auto after = testModule->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(frozen.rxNotifications, after.rxNotifications);
    TEST_ASSERT_EQUAL_UINT32(frozen.txValidDone, after.txValidDone);
    TEST_ASSERT_EQUAL_UINT32(frozen.txUnpaired, after.txUnpaired);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_GAPS, run.source)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT8(0, reply->decoded.payload.bytes[21]);
    packetPool.release(reply);
}

void test_radio_gaps_stop_pending_sent_observes_before_terminal_cleanup()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.source;
    sendControl(run, W12BenchmarkModule::Op::RESET, run.source);
    sendControl(run, W12BenchmarkModule::Op::START, run.source);
    TEST_ASSERT_EQUAL_INT(0, testModule->runOnce());
    TEST_ASSERT_EQUAL_UINT(1, testRadio->pendingCount());

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::STOP, run.source)));
    testRadio->finishAtWithOwnerTxNotification(0, 400);
    TEST_ASSERT_EQUAL_UINT(0, testRadio->pendingCount());
    const auto frozen = testModule->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(1, frozen.txValidDone);
    TEST_ASSERT_EQUAL_UINT32(1, frozen.txUnpaired);

    testModule->onOwnerRxNotification(500, 550, 0, 1, 0, 0, true);
    testModule->onOwnerTxNotification(600, true, true);
    const auto after = testModule->getRadioGapDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(frozen.rxNotifications, after.rxNotifications);
    TEST_ASSERT_EQUAL_UINT32(frozen.txValidDone, after.txValidDone);
    TEST_ASSERT_EQUAL_UINT32(frozen.txUnpaired, after.txUnpaired);

    TEST_ASSERT_EQUAL_INT(static_cast<int>(ProcessMessage::STOP),
                          static_cast<int>(sendControl(run, W12BenchmarkModule::Op::SNAPSHOT_RADIO_GAPS, run.source)));
    meshtastic_MeshPacket *reply = testModule->allocReply();
    TEST_ASSERT_NOT_NULL(reply);
    TEST_ASSERT_EQUAL_UINT8(0, reply->decoded.payload.bytes[21]);
    packetPool.release(reply);
}

static meshtastic_MeshPacket encryptedBenchmarkForAdminFallback(const W12BenchmarkModule::RunConfig &frame, PacketId packetId,
                                                                bool trustedAdmin = true)
{
    uint8_t senderPublic[32], senderPrivate[32], receiverPublic[32], receiverPrivate[32], wrongPublic[32], wrongPrivate[32];
    crypto->generateKeyPair(senderPublic, senderPrivate);
    crypto->generateKeyPair(receiverPublic, receiverPrivate);
    crypto->generateKeyPair(wrongPublic, wrongPrivate);
    auto packet = makeData(frame, 0);
    packet.id = packetId;
    // Fill the exact 239-byte encrypted radio candidate while keeping the W12 payload identity unchanged.
    packet.decoded.want_response = true;
    uint8_t plaintext[256];
    const size_t size = pb_encode_to_bytes(plaintext, sizeof(plaintext), &meshtastic_Data_msg, &packet.decoded);
    TEST_ASSERT_GREATER_THAN_UINT32(0, size);
    meshtastic_NodeInfoLite_public_key_t destinationKey = {};
    destinationKey.size = sizeof(receiverPublic);
    memcpy(destinationKey.bytes, receiverPublic, sizeof(receiverPublic));
    crypto->setDHPrivateKey(senderPrivate);
    TEST_ASSERT_TRUE(crypto->encryptCurve25519(frame.destination, frame.source, destinationKey, packet.id, size, plaintext,
                                               packet.encrypted.bytes));
    packet.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    packet.encrypted.size = size + MESHTASTIC_PKC_OVERHEAD;
    packet.channel = 0;
    packet.pki_encrypted = false;

    crypto->setDHPrivateKey(receiverPrivate);
    testNodeDB->clearTestNodes();
    testNodeDB->addPublicKey(frame.destination, receiverPublic);
    config.security.admin_key[0].size = sizeof(wrongPublic);
    memcpy(config.security.admin_key[0].bytes, wrongPublic, sizeof(wrongPublic));
    config.security.admin_key[1].size = trustedAdmin ? sizeof(senderPublic) : 0;
    memcpy(config.security.admin_key[1].bytes, senderPublic, sizeof(senderPublic));
    resetRoutingAuthEvaluationCount();
    resetAdminKeyFallbackBudget();
    return packet;
}

void test_pki_ccm_real_auth_gate_retains_failed_admin_attempt_without_double_counting_frame()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.destination;
    sendControl(run, W12BenchmarkModule::Op::RESET, run.destination);
    sendControl(run, W12BenchmarkModule::Op::START, run.destination);
    auto packet = encryptedBenchmarkForAdminFallback(run, 0x70123456);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(passesRoutingAuthGate(&packet)));
    TEST_ASSERT_EQUAL_UINT8(meshtastic_MeshPacket_encrypted_tag, packet.which_payload_variant);
    const auto timing = testModule->getPreSendAttributionDiagnostics().phaseTiming;
    TEST_ASSERT_TRUE(timing.pkiCcmAvailable);
    TEST_ASSERT_EQUAL_UINT32(2, timing.pkiCcmDecodeUs.count);
    TEST_ASSERT_EQUAL_UINT32(1, timing.rxGateDecodeUs.count);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(timing.pkiCcmDecodeUs.max, timing.pkiCcmDecodeUs.sum);
    // Repeating the same wire frame uses the auth cache and must not charge CCM twice.
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(passesRoutingAuthGate(&packet)));
    TEST_ASSERT_EQUAL_UINT32(2, testModule->getPreSendAttributionDiagnostics().phaseTiming.pkiCcmDecodeUs.count);
}

void test_pki_ccm_auth_gate_excludes_wrong_identity_mqtt_plain_and_failed_auth()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.destination;
    sendControl(run, W12BenchmarkModule::Op::RESET, run.destination);
    sendControl(run, W12BenchmarkModule::Op::START, run.destination);
    auto wrong = run;
    ++wrong.runId;
    auto packet = encryptedBenchmarkForAdminFallback(wrong, 0x70123457);
    passesRoutingAuthGate(&packet);
    packet = encryptedBenchmarkForAdminFallback(run, 0x70123458);
    packet.via_mqtt = true;
    passesRoutingAuthGate(&packet);
    packet = makeData(run, 1, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA, false);
    passesRoutingAuthGate(&packet);
    packet = encryptedBenchmarkForAdminFallback(run, 0x70123459, false);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::REJECT), static_cast<int>(passesRoutingAuthGate(&packet)));
    const auto timing = testModule->getPreSendAttributionDiagnostics().phaseTiming;
    TEST_ASSERT_FALSE(timing.pkiCcmAvailable);
    TEST_ASSERT_EQUAL_UINT32(0, timing.pkiCcmDecodeUs.count);
    TEST_ASSERT_EQUAL_UINT32(0, timing.rxGateDecodeUs.count);
}

void test_router_batch_selection_requires_exact_benchmark_candidate()
{
    const auto run = runConfig();
    myNodeInfo.my_node_num = run.destination;
    sendControl(run, W12BenchmarkModule::Op::RESET, run.destination);
    sendControl(run, W12BenchmarkModule::Op::START, run.destination);

    CryptoEngine *savedCrypto = crypto;
    RouterBatchSelectionProbe probe;
    crypto = &probe;

    auto matching = encryptedBenchmarkForAdminFallback(run, 0x70123500);
    const auto matchingVerdict = passesRoutingAuthGate(&matching);
    const bool matchingBatch = probe.sawBatchRequested;
    const auto matchingTiming = testModule->getPreSendAttributionDiagnostics().phaseTiming.pkiCcmDecodeUs;

    probe.clearSelection();
    auto wantsAck = encryptedBenchmarkForAdminFallback(run, 0x70123501);
    wantsAck.want_ack = true;
    const auto wantsAckVerdict = passesRoutingAuthGate(&wantsAck);
    const bool wantsAckBatch = probe.sawBatchRequested;

    probe.clearSelection();
    auto mqtt = encryptedBenchmarkForAdminFallback(run, 0x70123502);
    mqtt.via_mqtt = true;
    const auto mqttVerdict = passesRoutingAuthGate(&mqtt);
    const bool mqttBatch = probe.sawBatchRequested;

    probe.clearSelection();
    auto shorterRun = run;
    --shorterRun.size;
    auto shorter = encryptedBenchmarkForAdminFallback(shorterRun, 0x70123503);
    const auto shorterVerdict = passesRoutingAuthGate(&shorter);
    const bool shorterBatch = probe.sawBatchRequested;

    probe.clearSelection();
    auto foreignRun = run;
    foreignRun.source = 0x33333333;
    auto foreign = encryptedBenchmarkForAdminFallback(foreignRun, 0x70123504);
    const auto foreignVerdict = passesRoutingAuthGate(&foreign);
    const bool foreignBatch = probe.sawBatchRequested;

    crypto = savedCrypto;

    TEST_ASSERT_EQUAL_UINT(MAX_RADIO_PAYLOAD_LEN, matching.encrypted.size);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(matchingVerdict));
    TEST_ASSERT_TRUE(matchingBatch);
    TEST_ASSERT_TRUE(matchingTiming.count > 0);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(wantsAckVerdict));
    TEST_ASSERT_FALSE(wantsAckBatch);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(mqttVerdict));
    TEST_ASSERT_FALSE(mqttBatch);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(shorterVerdict));
    TEST_ASSERT_FALSE(shorterBatch);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(RoutingAuthVerdict::ACCEPT), static_cast<int>(foreignVerdict));
    TEST_ASSERT_FALSE(foreignBatch);
    TEST_ASSERT_EQUAL_UINT32(matchingTiming.count,
                             testModule->getPreSendAttributionDiagnostics().phaseTiming.pkiCcmDecodeUs.count);
}
#endif

void setUp()
{
    resetTestState();
}

void tearDown()
{
    if (testRadio)
        testRadio->releaseAll();
    while (testService) {
        meshtastic_MeshPacket *packet = testService->getForPhone();
        if (!packet)
            break;
        packetPool.release(packet);
    }
    while (testService) {
        meshtastic_QueueStatus *status = testService->getQueueStatusForPhone();
        if (!status)
            break;
        testService->releaseQueueStatusToPool(status);
    }
    Time::useRealClock();
    Time::resetMonotonicForTests();
}

void setup()
{
    initializeTestEnvironment();
    createFixture();
    UNITY_BEGIN();
    RUN_TEST(test_control_round_trip_preserves_run_identity);
    RUN_TEST(test_control_rejects_truncated_and_nonzero_reserved_bytes);
    RUN_TEST(test_config_bounds_reject_unbounded_runs);
    RUN_TEST(test_data_round_trip_keeps_exact_219_byte_shape_and_pattern);
    RUN_TEST(test_data_rejects_size_mismatch);
    RUN_TEST(test_data_decode_keeps_out_of_range_sequence_visible_to_admission);
    RUN_TEST(test_report_has_fixed_offsets_for_all_diagnostic_counters);
    RUN_TEST(test_diagnostic_snapshot_is_local_asof_and_keeps_existing_wire_formats);
    RUN_TEST(test_diagnostic_cca_events_are_aggregated_once_and_timing_uses_existing_slots);
    RUN_TEST(test_pre_send_attribution_tracks_only_valid_timer_dispatches);
    RUN_TEST(test_pre_send_attribution_page_is_fixed_and_local_without_radio_sample);
    RUN_TEST(test_phase_timing_extension_is_bounded_and_default_off);
    RUN_TEST(test_phase_timing_aggregates_wrap_deadline_and_saturate);
    RUN_TEST(test_pki_ccm_timing_aggregates_retry_calls_without_a_second_gate_sample);
#if W12_BENCHMARK_HAL_TIMING_ENABLED
    RUN_TEST(test_spi_yield_control_lifecycle_freezes_at_owned_terminal_boundary);
#endif
#if MESHTASTIC_W12_BENCHMARK_PHASE_TIMING
    RUN_TEST(test_radio_gaps_report_zero_and_overflow_encoding_is_strict);
    RUN_TEST(test_radio_gaps_controls_gate_completed_page_and_pair_owner_hooks);
    RUN_TEST(test_radio_gaps_reject_intervals_outside_finite_run_window);
    RUN_TEST(test_radio_gaps_stop_pending_cancel_freezes_page);
    RUN_TEST(test_radio_gaps_stop_pending_sent_observes_before_terminal_cleanup);
    RUN_TEST(test_router_batch_selection_requires_exact_benchmark_candidate);
    RUN_TEST(test_pki_ccm_real_auth_gate_retains_failed_admin_attempt_without_double_counting_frame);
    RUN_TEST(test_pki_ccm_auth_gate_excludes_wrong_identity_mqtt_plain_and_failed_auth);
#endif
    RUN_TEST(test_diagnostic_snapshot_accepts_zero_first_receiver_window);
    RUN_TEST(test_radio_diagnostic_page_tracks_authorization_stages_buckets_and_reset);
    RUN_TEST(test_radio_diagnostic_tail_keeps_rx_done_after_completion_with_pending_tx);
    RUN_TEST(test_rx_liveness_page_is_fixed_wire_and_local_authorized);
    RUN_TEST(test_rx_liveness_rearm_requires_receiver_window_and_radio_and_does_not_consume_budget);
    RUN_TEST(test_behavior_control_is_local_authorized_and_reset_is_not_mid_run);
    RUN_TEST(test_behavior_producer_uses_real_service_and_terminal_slots);
    RUN_TEST(test_behavior_receiver_requires_direct_authenticated_rf_and_validates_pattern);
    RUN_TEST(test_behavior_mesh_service_rejects_matching_api_data_but_accepts_registered_owner_send);
    const int result = UNITY_END();
    destroyFixture();
    exit(result);
}

void loop() {}

#else

void setup() {}
void loop() {}

#endif
