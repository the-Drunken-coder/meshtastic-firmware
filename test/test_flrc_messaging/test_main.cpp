// Active FLRC must retain the native router's AES/PKI envelopes, explicit ACK handling,
// frame ceiling, opaque forwarding and duplicate suppression. The radio seam captures
// production frame packing and injects reception metadata; it proves no RF behavior.
// Exercises Router::send() and perhapsDecode() in src/mesh/Router.cpp,
// ReliableRouter::ackProofStatusFor() in src/mesh/ReliableRouter.cpp, and
// RadioInterface::beginSending() in src/mesh/RadioInterface.cpp. These contracts prevent
// a modulation change from bypassing encryption, accepting unauthenticated ACKs, or
// forwarding frames outside the existing size and hop limits.
#include "MeshTypes.h"
#include "TestUtil.h"
#include "airtime.h"
#include "mesh/Channels.h"
#include "mesh/CryptoEngine.h"
#include "mesh/MeshModule.h"
#include "mesh/NodeDB.h"
#include "mesh/RadioMode.h"
#include "mesh/ReliableRouter.h"
#include "mesh/W12FlrcProfile.h"
#include "modules/RoutingModule.h"
#include "support/MockMeshService.h"
#include <array>
#include <cstring>
#include <memory>
#include <pb_encode.h>
#include <vector>

namespace
{
constexpr NodeNum SENDER_ID = 0x11111111;
constexpr NodeNum RECEIVER_ID = 0x22222222;
constexpr NodeNum RELAY_ID = 0x33333333;

class TestNodeDB : public NodeDB
{
  public:
    void install(NodeNum num, const uint8_t *key)
    {
        meshtastic_NodeInfoLite node = meshtastic_NodeInfoLite_init_zero;
        node.num = num;
        node.public_key.size = 32;
        memcpy(node.public_key.bytes, key, 32);
        nodeInfoLiteSetBit(&node, NODEINFO_BITFIELD_HAS_USER_MASK, true);
        nodes.push_back(node);
        meshNodes = &nodes;
        numMeshNodes = nodes.size();
    }

  private:
    std::vector<meshtastic_NodeInfoLite> nodes;
};

class CaptureRadio : public RadioInterface
{
  public:
    ErrorCode send(meshtastic_MeshPacket *packet) override
    {
        const size_t length = beginSending(packet);
        frameLengths.push_back(length);
        packets.push_back(*packet);
        sendingPacket = nullptr;
        packetPool.release(packet);
        return ERRNO_OK;
    }
    uint32_t getPacketTime(uint32_t length, bool = false) override { return W12FlrcProfile::durationMs(length); }
    std::vector<meshtastic_MeshPacket> packets;
    std::vector<size_t> frameLengths;
};

class TestRouter : public ReliableRouter
{
  public:
    size_t retries() const { return pending.size(); }
    void clearRetries()
    {
        while (!pending.empty())
            stopRetransmission(pending.begin()->first);
    }
};

class CaptureModule : public MeshModule
{
  public:
    CaptureModule() : MeshModule("flrc-message-capture") {}
    bool wantPacket(const meshtastic_MeshPacket *packet) override
    {
        return packet->which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
               packet->decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP;
    }
    ProcessMessage handleReceived(const meshtastic_MeshPacket &packet) override
    {
        packets.push_back(packet);
        return ProcessMessage::CONTINUE;
    }
    std::vector<meshtastic_MeshPacket> packets;
};

struct Endpoint {
    NodeNum num;
    std::array<uint8_t, 32> publicKey;
    std::array<uint8_t, 32> privateKey;
    std::unique_ptr<TestRouter> router;
    CaptureRadio *radio;
};

struct SavedGlobals {
    meshtastic_LocalConfig config;
    meshtastic_LocalModuleConfig moduleConfig;
    meshtastic_ChannelFile channelFile;
    meshtastic_User owner;
    meshtastic_MyNodeInfo myNodeInfo;
    NodeDB *nodeDB;
    Router *router;
    MeshService *service;
    RoutingModule *routingModule;
    AirTime *airTime;
};

SavedGlobals saved;
std::unique_ptr<TestNodeDB> database;
std::unique_ptr<MockMeshService> meshService;
std::unique_ptr<RoutingModule> routing;
std::unique_ptr<CaptureModule> capture;
std::unique_ptr<AirTime> airtime;
std::array<Endpoint, 3> endpoints;

void activate(Endpoint &endpoint)
{
    myNodeInfo.my_node_num = endpoint.num;
    owner.public_key.size = 32;
    memcpy(owner.public_key.bytes, endpoint.publicKey.data(), 32);
    config.security.private_key.size = 32;
    config.security.public_key.size = 32;
    memcpy(config.security.private_key.bytes, endpoint.privateKey.data(), 32);
    memcpy(config.security.public_key.bytes, endpoint.publicKey.data(), 32);
    // Boot restores both ECDH and signing keys; the low-level DH setter leaves signing keys unchanged.
    std::array<uint8_t, 32> restoredPublicKey;
    TEST_ASSERT_TRUE(crypto->regeneratePublicKey(restoredPublicKey.data(), endpoint.privateKey.data()));
    TEST_ASSERT_EQUAL_MEMORY(endpoint.publicKey.data(), restoredPublicKey.data(), restoredPublicKey.size());
    router = endpoint.router.get();
}

meshtastic_MeshPacket *textPacket(NodeNum to, size_t payloadSize, bool wantAck = false)
{
    auto *packet = router->allocForSending();
    TEST_ASSERT_NOT_NULL(packet);
    packet->to = to;
    packet->channel = 0;
    packet->want_ack = wantAck;
    packet->decoded.portnum = meshtastic_PortNum_TEXT_MESSAGE_APP;
    packet->decoded.payload.size = payloadSize;
    for (size_t i = 0; i < payloadSize; ++i)
        packet->decoded.payload.bytes[i] = 'a' + i % 26;
    return packet;
}

void receive(const meshtastic_MeshPacket &frame)
{
    auto *packet = packetPool.allocCopy(frame);
    TEST_ASSERT_NOT_NULL(packet);
    packet->transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    packet->has_rx_rssi = true;
    packet->rx_rssi = -75;
    packet->rx_snr = 0;
    packet->rx_snr_unavailable = true;
    router->enqueueReceivedMessage(packet);
    router->runOnce();
}

void assertText(const meshtastic_MeshPacket &received, const meshtastic_MeshPacket &original)
{
    TEST_ASSERT_EQUAL_UINT32(original.id, received.id);
    TEST_ASSERT_EQUAL_UINT32(original.from, received.from);
    TEST_ASSERT_EQUAL_UINT32(original.to, received.to);
    TEST_ASSERT_EQUAL_UINT32(original.decoded.payload.size, received.decoded.payload.size);
    TEST_ASSERT_EQUAL_MEMORY(original.decoded.payload.bytes, received.decoded.payload.bytes, original.decoded.payload.size);
    TEST_ASSERT_TRUE(received.rx_snr_unavailable);
    TEST_ASSERT_EQUAL_INT(-75, received.rx_rssi);
}

void test_flrc_broadcast_uses_channel_cipher_and_delivers_without_measured_snr()
{
    activate(endpoints[0]);
    auto *packet = textPacket(NODENUM_BROADCAST, 80);
    const auto original = *packet;
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, router->send(packet));
    const auto frame = endpoints[0].radio->packets.back();
    TEST_ASSERT_EQUAL(meshtastic_MeshPacket_encrypted_tag, frame.which_payload_variant);
    TEST_ASSERT_FALSE(frame.pki_encrypted);
    TEST_ASSERT_FALSE(memcmp(original.decoded.payload.bytes, frame.encrypted.bytes, original.decoded.payload.size) == 0);

    activate(endpoints[1]);
    receive(frame);
    TEST_ASSERT_EQUAL_UINT32(1, capture->packets.size());
    assertText(capture->packets.back(), original);
    TEST_ASSERT_FALSE(nodeInfoLiteHasSnr(database->getMeshNode(SENDER_ID)));
    TEST_ASSERT_TRUE(database->heardOnCurrentRadio(database->getMeshNode(SENDER_ID)));
}

#if !MESHTASTIC_EXCLUDE_PKI
void test_flrc_pki_dm_generates_real_ack_and_stops_sender_retries()
{
    activate(endpoints[0]);
    auto *packet = textPacket(RECEIVER_ID, 80, true);
    const auto original = *packet;
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, router->send(packet));
    TEST_ASSERT_EQUAL_UINT32(1, endpoints[0].router->retries());
    const auto frame = endpoints[0].radio->packets.back();
    TEST_ASSERT_TRUE(frame.pki_encrypted);

    activate(endpoints[1]);
    receive(frame);
    TEST_ASSERT_EQUAL_UINT32(1, capture->packets.size());
    assertText(capture->packets.back(), original);
    TEST_ASSERT_TRUE(capture->packets.back().pki_encrypted);
    TEST_ASSERT_EQUAL_UINT32(1, endpoints[1].radio->packets.size());
    const auto ack = endpoints[1].radio->packets.back();
    TEST_ASSERT_EQUAL_UINT32(SENDER_ID, ack.to);

    activate(endpoints[0]);
    auto decodedAck = ack;
    TEST_ASSERT_EQUAL(DecodeState::DECODE_SUCCESS, perhapsDecode(&decodedAck));
    TEST_ASSERT_EQUAL(meshtastic_PortNum_ROUTING_APP, decodedAck.decoded.portnum);
    TEST_ASSERT_EQUAL_UINT32(original.id, decodedAck.decoded.request_id);
    receive(ack);
    TEST_ASSERT_EQUAL_UINT32(0, endpoints[0].router->retries());
    TEST_ASSERT_EQUAL(meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_VALID, router->ackProofStatusFor(ack));
}

void test_flrc_opaque_relay_preserves_pki_ciphertext_and_suppresses_relay_duplicates()
{
    activate(endpoints[0]);
    auto *packet = textPacket(RECEIVER_ID, 40);
    const auto original = *packet;
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, router->send(packet));
    auto frame = endpoints[0].radio->packets.back();
    TEST_ASSERT_TRUE(frame.pki_encrypted);
    // A copy already forwarded by another relay must be deduplicated, unlike an originator retry.
    frame.hop_limit--;
    activate(endpoints[2]);
    receive(frame);
    TEST_ASSERT_EQUAL_UINT32(1, endpoints[2].radio->packets.size());
    TEST_ASSERT_EQUAL_UINT32(0, capture->packets.size());
    const auto forwarded = endpoints[2].radio->packets.back();
    TEST_ASSERT_EQUAL_UINT32(frame.id, forwarded.id);
    TEST_ASSERT_EQUAL_UINT32(frame.from, forwarded.from);
    TEST_ASSERT_EQUAL_UINT32(frame.to, forwarded.to);
    TEST_ASSERT_EQUAL_UINT8(frame.hop_limit - 1, forwarded.hop_limit);
    TEST_ASSERT_EQUAL_UINT8(RELAY_ID & 0xff, forwarded.relay_node);
    TEST_ASSERT_EQUAL_UINT32(frame.encrypted.size, forwarded.encrypted.size);
    TEST_ASSERT_EQUAL_MEMORY(frame.encrypted.bytes, forwarded.encrypted.bytes, frame.encrypted.size);
    receive(frame);
    TEST_ASSERT_EQUAL_UINT32(1, endpoints[2].radio->packets.size());

    activate(endpoints[1]);
    receive(forwarded);
    TEST_ASSERT_EQUAL_UINT32(1, capture->packets.size());
    assertText(capture->packets.back(), original);
    receive(forwarded);
    TEST_ASSERT_EQUAL_UINT32(1, capture->packets.size());
}

void test_flrc_pki_preserves_complete_frame_ceiling()
{
    activate(endpoints[0]);
    auto *packet = textPacket(RECEIVER_ID, 0);
    // perhapsEncode adds this presence bit for locally originated packets before measuring the envelope.
    packet->decoded.has_bitfield = true;
    size_t encodedSize = 0;
    while (packet->decoded.payload.size < sizeof(packet->decoded.payload.bytes)) {
        packet->decoded.payload.size++;
        TEST_ASSERT_TRUE(pb_get_encoded_size(&encodedSize, &meshtastic_Data_msg, &packet->decoded));
        if (encodedSize + sizeof(PacketHeader) + MESHTASTIC_PKC_OVERHEAD > MAX_LORA_PAYLOAD_LEN)
            break;
    }
    const auto oversized = *packet;
    packet->decoded.payload.size--;
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, router->send(packet));
    TEST_ASSERT_EQUAL_UINT32(MAX_LORA_PAYLOAD_LEN, endpoints[0].radio->frameLengths.back());
    TEST_ASSERT_TRUE(endpoints[0].radio->packets.back().pki_encrypted);
    const size_t before = endpoints[0].radio->packets.size();
    packet = packetPool.allocCopy(oversized);
    TEST_ASSERT_NOT_NULL(packet);
    TEST_ASSERT_EQUAL_INT(meshtastic_Routing_Error_TOO_LARGE, router->send(packet));
    TEST_ASSERT_EQUAL_UINT32(before, endpoints[0].radio->packets.size());
}
#endif
} // namespace

void setUp()
{
    saved = {config, moduleConfig, channelFile, owner, myNodeInfo, nodeDB, router, service, routingModule, airTime};
    database = std::make_unique<TestNodeDB>();
    nodeDB = database.get();
    config = meshtastic_LocalConfig_init_zero;
    moduleConfig = meshtastic_LocalModuleConfig_init_zero;
    owner = meshtastic_User_init_zero;
    config.lora.has_radio_mode = true;
    config.lora.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_FLRC;
    config.lora.region = meshtastic_Config_LoRaConfig_RegionCode_US;
    config.lora.tx_enabled = true;
    config.lora.override_duty_cycle = true;
    config.lora.hop_limit = 3;
    config.device.role = meshtastic_Config_DeviceConfig_Role_CLIENT;
    config.device.rebroadcast_mode = meshtastic_Config_DeviceConfig_RebroadcastMode_ALL;
    RadioMode::initialize(config.lora);
    RadioMode::markInitialized(true);
    database->refreshCommittedLoraSlot();
    channelFile = meshtastic_ChannelFile_init_zero;
    channelFile.channels_count = 1;
    auto &channel = channelFile.channels[0];
    channel.index = 0;
    channel.role = meshtastic_Channel_Role_PRIMARY;
    channel.has_settings = true;
    strcpy(channel.settings.name, "flrc-test");
    channel.settings.psk.size = 16;
    memset(channel.settings.psk.bytes, 0x5a, 16);
    channels.onConfigChanged();
    airtime = std::make_unique<AirTime>();
    airTime = airtime.get();
    meshService = std::make_unique<MockMeshService>();
    service = meshService.get();
    routing = std::make_unique<RoutingModule>();
    routingModule = routing.get();
    capture = std::make_unique<CaptureModule>();
    const NodeNum ids[] = {SENDER_ID, RECEIVER_ID, RELAY_ID};
    for (size_t i = 0; i < endpoints.size(); ++i) {
        auto &endpoint = endpoints[i];
        endpoint.num = ids[i];
        crypto->generateKeyPair(endpoint.publicKey.data(), endpoint.privateKey.data());
        database->install(endpoint.num, endpoint.publicKey.data());
        endpoint.router = std::make_unique<TestRouter>();
        auto radio = std::make_unique<CaptureRadio>();
        endpoint.radio = radio.get();
        endpoint.router->addInterface(std::move(radio));
    }
    activate(endpoints[0]);
}

void tearDown()
{
    while (auto *packet = meshService->getForPhone())
        meshService->releaseToPool(packet);
    while (auto *status = meshService->getQueueStatusForPhone())
        meshService->releaseQueueStatusToPool(status);
    capture.reset();
    routing.reset();
    router = nullptr;
    for (auto &endpoint : endpoints) {
        endpoint.router->clearRetries();
        endpoint.router.reset();
        endpoint.radio = nullptr;
    }
    meshService.reset();
    database.reset();
    airtime.reset();
    config = saved.config;
    moduleConfig = saved.moduleConfig;
    channelFile = saved.channelFile;
    owner = saved.owner;
    myNodeInfo = saved.myNodeInfo;
    nodeDB = saved.nodeDB;
    router = saved.router;
    service = saved.service;
    routingModule = saved.routingModule;
    airTime = saved.airTime;
    if (channelFile.channels_count)
        channels.onConfigChanged();
    RadioMode::initialize(config.lora);
    if (config.security.private_key.size == 32)
        crypto->regeneratePublicKey(config.security.public_key.bytes, config.security.private_key.bytes);
}

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_flrc_broadcast_uses_channel_cipher_and_delivers_without_measured_snr);
#if !MESHTASTIC_EXCLUDE_PKI
    RUN_TEST(test_flrc_pki_dm_generates_real_ack_and_stops_sender_retries);
    RUN_TEST(test_flrc_opaque_relay_preserves_pki_ciphertext_and_suppresses_relay_duplicates);
    RUN_TEST(test_flrc_pki_preserves_complete_frame_ceiling);
#endif
    exit(UNITY_END());
}

void loop() {}
