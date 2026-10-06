// ReliableRouter ACK/NAK decision matrix: which ACK or NAK sniffReceived() emits per inbound
// shape, retransmission bookkeeping, the #11502 implicit ACK for our own overheard opaque DM
// (Group 5b drives the real OPAQUE_RELAY_ONLY ingress path), the pending-timer extensions, and the
// ack proof verdict reported to the phone (Group 4b).
// Harness copied from test_nexthop_routing (ReliableRouterTestShim + MockRoutingModule).

#include "MeshTypes.h" // before TestUtil.h: provides NodeNum etc.
#include "TestUtil.h"
#include <array>
#include <unity.h>

#include "UptimeClock.h"
#include "airtime.h"
#include "configuration.h"
#include "gps/RTC.h"
#include "mesh/Channels.h"
#include "mesh/MeshPacketQueue.h"
#include "mesh/NodeDB.h"
#include "mesh/RadioInterface.h"
#include "mesh/ReliableRouter.h"
#include "mesh/Throttle.h"
#include "mesh/mesh-pb-constants.h"
#include "modules/RoutingModule.h"
#if !(MESHTASTIC_EXCLUDE_PKI)
#include "mesh/AckProof.h"
#include "mesh/CryptoEngine.h"
#endif
#include <cstdio>
#include <cstring>
#include <list>
#include <memory>
#include <tuple>
#include <vector>

static constexpr NodeNum kLocalNode = 0x11111111; // last byte 0x11
static constexpr NodeNum kRemoteNode = 0x22222222;
static constexpr NodeNum kThirdNode = 0x33333333;

// ---------------------------------------------------------------------------
// MockNodeDB - inject sender records with a controlled public-key size, so the PKI_UNKNOWN_PUBKEY
// vs NO_CHANNEL discrimination in sniffReceived() can be driven per test.
// ---------------------------------------------------------------------------
class MockNodeDB : public NodeDB
{
  public:
    void clearTestNodes()
    {
        testNodes.clear();
        meshNodes = &testNodes;
        numMeshNodes = 0;
    }

    void addNode(NodeNum num, uint8_t publicKeySize = 0)
    {
        meshtastic_NodeInfoLite node = meshtastic_NodeInfoLite_init_zero;
        node.num = num;
        node.last_heard = getTime();
        node.public_key.size = publicKeySize;
        if (publicKeySize)
            memset(node.public_key.bytes, 0x5C, publicKeySize);
        nodeInfoLiteSetBit(&node, NODEINFO_BITFIELD_HAS_USER_MASK, true);
        testNodes.push_back(node);
        meshNodes = &testNodes;
        numMeshNodes = testNodes.size();
    }

    void addNodeWithKey(NodeNum num, const uint8_t *publicKey)
    {
        addNode(num, 32);
        memcpy(testNodes.back().public_key.bytes, publicKey, 32);
    }

    std::vector<meshtastic_NodeInfoLite> testNodes;
};

// ---------------------------------------------------------------------------
// Test shim - expose the protected sniff/filter entry points and the pending/route-health state.
// ---------------------------------------------------------------------------
class ReliableRouterTestShim : public ReliableRouter
{
  public:
    ReliableRouterTestShim() : ReliableRouter() {}

    using NextHopRouter::findRouteHealth;
    using NextHopRouter::noteRouteFailure;
    using NextHopRouter::noteRouteLearned;

    size_t pendingCount() const { return pending.size(); }

    void seedRetry(const meshtastic_MeshPacket &p, uint8_t attempts)
    {
        auto *copy = packetPool.allocCopy(p);
        TEST_ASSERT_NOT_NULL(copy);
        auto *entry = startRetransmission(copy, attempts);
        TEST_ASSERT_NOT_NULL(entry);
        // These fixtures represent a packet that has already crossed the radio boundary. They do
        // not enqueue a physical packet, so make the ACK-wait state explicit instead of relying on
        // the production queue lifecycle.
        entry->waitingForAck = true;
        entry->hasTransmitted = true;
        setNextTx(entry);
    }

    void sniffForTest(const meshtastic_MeshPacket *p, const meshtastic_Routing *routing)
    {
        ReliableRouter::sniffReceived(p, routing);
    }

    int32_t runDueRetries() { return doRetransmissions(); }

    bool stopForTest(NodeNum from, PacketId id) { return stopRetransmission(from, id); }

    bool filterForTest(const meshtastic_MeshPacket *p) { return ReliableRouter::shouldFilterReceived(p); }

    bool hasPending(NodeNum from, PacketId id) { return findPendingPacket(from, id) != nullptr; }

    uint32_t pendingNextTx(NodeNum from, PacketId id)
    {
        PendingPacket *entry = findPendingPacket(from, id);
        TEST_ASSERT_NOT_NULL(entry);
        return entry->nextTxMsec;
    }

    const meshtastic_MeshPacket *pendingPacket(NodeNum from, PacketId id)
    {
        PendingPacket *entry = findPendingPacket(from, id);
        TEST_ASSERT_NOT_NULL(entry);
        return entry->packet;
    }

    uint8_t pendingRetries(NodeNum from, PacketId id)
    {
        PendingPacket *entry = findPendingPacket(from, id);
        TEST_ASSERT_NOT_NULL(entry);
        return entry->numRetransmissions;
    }

    bool pendingWaitsForAck(NodeNum from, PacketId id)
    {
        PendingPacket *entry = findPendingPacket(from, id);
        TEST_ASSERT_NOT_NULL(entry);
        return entry->waitingForAck;
    }

    bool pendingRadioCandidateIsClear(NodeNum from, PacketId id)
    {
        PendingPacket *entry = findPendingPacket(from, id);
        TEST_ASSERT_NOT_NULL(entry);
        return entry->radioCandidate == nullptr;
    }

    void clearPendingForTest()
    {
        while (!pending.empty())
            stopRetransmission(pending.begin()->first);
    }

    void resetRouteHealthForTest()
    {
        for (auto &h : routeHealth)
            h = RouteHealth{};
    }
};

// Capture radio with a configurable per-packet airtime, so the pending-timer extension loops
// (which are no-ops with a 0-returning stub) become observable.
class TimedCaptureRadio : public RadioInterface
{
  public:
    ErrorCode send(meshtastic_MeshPacket *p) override
    {
        if (deferTransmissions) {
            bool dropped = false;
            meshtastic_MeshPacket *evicted = nullptr;
            if (!txQueue.enqueue(p, &dropped, &evicted)) {
                notifyTxFinished(p, TxState::Rejected);
                packetPool.release(p);
                return ERRNO_UNKNOWN;
            }
            if (evicted) {
                notifyTxFinished(evicted, TxState::Dropped);
                packetPool.release(evicted);
            }
            return ERRNO_OK;
        }

        sentPackets.push_back(*p);
        const uint32_t generation = notifyTxStarted(p);
        notifyTxFinished(p, TxState::Sent, generation);
        packetPool.release(p);
        return ERRNO_OK;
    }

    bool cancelSending(NodeNum from, PacketId id) override
    {
        if (deferTransmissions) {
            auto *p = txQueue.remove(from, id);
            if (p) {
                notifyTxFinished(p, TxState::Cancelled);
                packetPool.release(p);
            }
            return p != nullptr;
        }

        cancelCount++;
        return false;
    }

    bool findInTxQueue(NodeNum from, PacketId id) override
    {
        if (deferTransmissions)
            return txQueue.find(from, id);

        (void)from;
        (void)id;
        return false;
    }

    uint32_t getPacketTime(uint32_t totalPacketLen, bool received = false) override
    {
        (void)totalPacketLen;
        (void)received;
        return packetTimeMsec;
    }

    void reset()
    {
        while (auto *p = txQueue.dequeue()) {
            notifyTxFinished(p, TxState::Cancelled);
            packetPool.release(p);
        }
        if (transmitting) {
            notifyTxFinished(transmitting, TxState::Cancelled, transmitGeneration);
            packetPool.release(transmitting);
            transmitting = nullptr;
            transmitGeneration = 0;
        }
        sentPackets.clear();
        cancelCount = 0;
        packetTimeMsec = 0;
        deferTransmissions = false;
    }

    bool startTransmissionForTest()
    {
        if (transmitting)
            return false;
        transmitting = txQueue.dequeue();
        if (!transmitting)
            return false;
        sentPackets.push_back(*transmitting);
        transmitGeneration = notifyTxStarted(transmitting);
        return true;
    }

    bool completeTransmissionForTest(TxState result = TxState::Sent)
    {
        if (!transmitting)
            return false;
        notifyTxFinished(transmitting, result, transmitGeneration);
        packetPool.release(transmitting);
        transmitting = nullptr;
        transmitGeneration = 0;
        return true;
    }

    size_t queuedCount() { return txQueue.getMaxLen() - txQueue.getFree(); }

    std::vector<meshtastic_MeshPacket> sentPackets;
    uint32_t cancelCount = 0;
    uint32_t packetTimeMsec = 0;
    bool deferTransmissions = false;

  private:
    MeshPacketQueue txQueue = MeshPacketQueue(MAX_TX_QUEUE);
    meshtastic_MeshPacket *transmitting = nullptr;
    uint32_t transmitGeneration = 0;
};

class MockRoutingModule : public RoutingModule
{
  public:
    // The relaying copy the caller handed us, flattened to the fields allocAckNak() forwards onto
    // the ack. One entry per sendAckNak() call, so it stays aligned with ackNaks.
    struct RelaySource {
        bool present;
        uint8_t relayNode;
        bool hasRxRssi;
        int32_t rxRssi;
        float rxSnr;
    };

    void sendAckNak(meshtastic_Routing_Error err, NodeNum to, PacketId idFrom, ChannelIndex chIndex, uint8_t hopLimit = 0,
                    bool ackWantsAck = false, const meshtastic_MeshPacket *relaySource = nullptr) override
    {
        ackNaks.emplace_back(err, to, idFrom, chIndex, hopLimit, ackWantsAck);
        if (relaySource)
            relaySources.push_back(
                {true, relaySource->relay_node, relaySource->has_rx_rssi, relaySource->rx_rssi, relaySource->rx_snr});
        else
            relaySources.push_back({false, NO_RELAY_NODE, false, 0, 0.0f});
    }

    std::list<std::tuple<meshtastic_Routing_Error, NodeNum, PacketId, ChannelIndex, uint8_t, bool>> ackNaks;
    std::vector<RelaySource> relaySources;
};

class ScopedAirTimeFixture
{
  public:
    ScopedAirTimeFixture() : previous(airTime) { airTime = &instance; }
    ~ScopedAirTimeFixture() { airTime = previous; }

  private:
    AirTime instance;
    AirTime *previous;
};

static MockNodeDB *mockNodeDB = nullptr;
static ReliableRouterTestShim *reliableShim = nullptr;
static TimedCaptureRadio *radio = nullptr;
static MockRoutingModule *mockRoutingModule = nullptr;
static std::unique_ptr<ScopedAirTimeFixture> airTimeFixture;
static PacketId nextTestPacketId = 0x7A000000;

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

static meshtastic_MeshPacket makeDecodedPacket(meshtastic_PortNum portnum, NodeNum from, NodeNum to, uint8_t channel,
                                               bool wantAck = false)
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.from = from;
    p.to = to;
    p.id = nextTestPacketId++;
    p.channel = channel;
    p.hop_start = 3;
    p.hop_limit = 3; // hop_start == hop_limit -> getHopsAway() == 0 ("heard directly")
    p.relay_node = 0x22;
    p.next_hop = NO_NEXT_HOP_PREFERENCE;
    p.want_ack = wantAck;
    p.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    p.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    p.decoded.portnum = portnum;
    return p;
}

static meshtastic_MeshPacket makeEncryptedToUs(uint8_t channel, bool wantAck)
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.from = kRemoteNode;
    p.to = kLocalNode;
    p.id = nextTestPacketId++;
    p.channel = channel;
    p.hop_start = 3;
    p.hop_limit = 3;
    p.relay_node = 0x22;
    p.next_hop = NO_NEXT_HOP_PREFERENCE;
    p.want_ack = wantAck;
    p.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    p.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    p.encrypted.size = 32;
    return p;
}

static void expectSingleAckNak(meshtastic_Routing_Error err, NodeNum to, PacketId id, ChannelIndex chIndex, uint8_t hopLimit,
                               bool ackWantsAck)
{
    TEST_ASSERT_EQUAL_UINT32(1, mockRoutingModule->ackNaks.size());
    const auto &ack = mockRoutingModule->ackNaks.front();
    TEST_ASSERT_EQUAL_INT(err, std::get<0>(ack));
    TEST_ASSERT_EQUAL_HEX32(to, std::get<1>(ack));
    TEST_ASSERT_EQUAL_HEX32(id, std::get<2>(ack));
    TEST_ASSERT_EQUAL_UINT8(chIndex, std::get<3>(ack));
    TEST_ASSERT_EQUAL_UINT8(hopLimit, std::get<4>(ack));
    TEST_ASSERT_EQUAL(ackWantsAck, std::get<5>(ack));
}

// #10767: only the implicit ack for an overheard rebroadcast of our own packet carries a relay
// source; every other ACK/NAK must leave it unset so the phone is never told a relayer we did not
// hear.
static void expectRelaySource(uint8_t relayNode, int32_t rxRssi, float rxSnr)
{
    TEST_ASSERT_EQUAL_UINT32(1, mockRoutingModule->relaySources.size());
    const auto &relay = mockRoutingModule->relaySources.front();
    TEST_ASSERT_TRUE(relay.present);
    TEST_ASSERT_EQUAL_HEX8(relayNode, relay.relayNode);
    TEST_ASSERT_TRUE(relay.hasRxRssi);
    TEST_ASSERT_EQUAL_INT32(rxRssi, relay.rxRssi);
    TEST_ASSERT_EQUAL_FLOAT(rxSnr, relay.rxSnr);
}

static void expectNoRelaySource()
{
    TEST_ASSERT_EQUAL_UINT32(1, mockRoutingModule->relaySources.size());
    TEST_ASSERT_FALSE(mockRoutingModule->relaySources.front().present);
}

static void configureChannels()
{
    memset(&channelFile, 0, sizeof(channelFile));
    channelFile.channels_count = 2;

    meshtastic_Channel primary = meshtastic_Channel_init_default;
    primary.index = 0;
    primary.has_settings = true;
    primary.role = meshtastic_Channel_Role_PRIMARY;
    strncpy(primary.settings.name, "primary", sizeof(primary.settings.name) - 1);

    meshtastic_Channel secondary = meshtastic_Channel_init_default;
    secondary.index = 1;
    secondary.has_settings = true;
    secondary.role = meshtastic_Channel_Role_SECONDARY;
    strncpy(secondary.settings.name, "second", sizeof(secondary.settings.name) - 1);
    secondary.settings.psk.size = 32;
    memset(secondary.settings.psk.bytes, 0xAB, secondary.settings.psk.size);

    channelFile.channels[0] = primary;
    channelFile.channels[1] = secondary;
    channels.onConfigChanged();
}

void setUp(void)
{
    Time::useRealClock();
    myNodeInfo.my_node_num = kLocalNode;
    config.device.role = meshtastic_Config_DeviceConfig_Role_CLIENT;
    config.device.rebroadcast_mode = meshtastic_Config_DeviceConfig_RebroadcastMode_ALL;
    config.lora.override_duty_cycle = true;
    config.lora.hop_limit = 3; // keep getHopLimitForResponse() deterministic across tests
    config.security.private_key.size = 0;
    owner.is_licensed = false;
    // Keep our own key unset: the PKI_UNKNOWN_PUBKEY NAK handler dereferences nodeInfoModule (a null
    // global here) only when owner.public_key.size == 32.
    owner.public_key.size = 0;
    mockNodeDB->clearTestNodes();
    reliableShim->clearPendingForTest();
    reliableShim->resetRouteHealthForTest();
    radio->reset();
    mockRoutingModule->ackNaks.clear();
    mockRoutingModule->relaySources.clear();
    configureChannels();
}

void tearDown(void)
{
    reliableShim->clearPendingForTest();
    radio->reset();
    myNodeInfo.my_node_num = kLocalNode;
    config.security.private_key.size = 0;
    owner.public_key.size = 0;
    Time::useRealClock();
}

// ===========================================================================
// Group 1 - want_ack ACK variants (decoded packets to us)
// ===========================================================================

void test_text_dm_want_ack_gets_want_ack_ack(void)
{
    auto p = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/true);
    p.relay_node = 0x77; // this ACK travels the mesh for someone else's DM; it must claim no relayer
    p.has_rx_rssi = true;
    p.rx_rssi = -55;
    uint8_t expectedHop = mockRoutingModule->getHopLimitForResponse(p);
    TEST_ASSERT_NOT_EQUAL(0, expectedHop); // must be distinguishable from the 0-hop ACK branch

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kRemoteNode, p.id, 1, expectedHop, /*ackWantsAck=*/true);
    expectNoRelaySource();
}

void test_text_reply_still_gets_want_ack_ack(void)
{
    // shouldSuccessAckWithWantAck() runs before the response branch, so a text DM that is itself a
    // reply still gets the reliable want-ack ACK (not the 0-hop response treatment).
    auto p = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/true);
    p.decoded.reply_id = 0x1234;
    uint8_t expectedHop = mockRoutingModule->getHopLimitForResponse(p);

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kRemoteNode, p.id, 1, expectedHop, /*ackWantsAck=*/true);
}

void test_nontext_dm_want_ack_gets_plain_ack(void)
{
    auto p = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/true);
    uint8_t expectedHop = mockRoutingModule->getHopLimitForResponse(p);
    TEST_ASSERT_NOT_EQUAL(0, expectedHop);

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kRemoteNode, p.id, 1, expectedHop, /*ackWantsAck=*/false);
}

void test_response_heard_directly_gets_zero_hop_ack(void)
{
    // A response (request_id set) heard at 0 hops: the original sender cannot overhear an implicit
    // ACK, so we ACK - but only with hop limit 0.
    auto p = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/true);
    p.decoded.request_id = 0x4242;

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kRemoteNode, p.id, 1, /*hopLimit=*/0, /*ackWantsAck=*/false);
}

void test_response_relayed_gets_no_ack(void)
{
    // A relayed response with no next-hop addressing already got its implicit ACK from the
    // rebroadcast; ACKing again would only burn airtime.
    auto p = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/true);
    p.decoded.request_id = 0x4242;
    p.hop_limit = 2; // hop_start 3 -> 1 hop away

    reliableShim->sniffForTest(&p, nullptr);

    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
}

void test_response_relayed_via_next_hop_gets_zero_hop_ack(void)
{
    // Relayed, but directed at a next_hop: the immediate relayer retransmits until stopped, so a
    // 0-hop ACK is still required.
    auto p = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/true);
    p.decoded.request_id = 0x4242;
    p.hop_limit = 2;
    p.next_hop = 0x77;

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kRemoteNode, p.id, 1, /*hopLimit=*/0, /*ackWantsAck=*/false);
}

void test_broadcast_want_ack_gets_no_ack(void)
{
    // 0-hop reliability is unicast-only: a want_ack broadcast is never ACKed (isToUs() is false).
    auto p = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kRemoteNode, NODENUM_BROADCAST, 0, /*wantAck=*/true);

    reliableShim->sniffForTest(&p, nullptr);

    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
}

// ===========================================================================
// Group 2 - undecodable want_ack NAKs (encrypted packets to us)
// ===========================================================================

void test_pki_unknown_sender_gets_pki_unknown_pubkey_nak(void)
{
    // channel==0 + sender absent from NodeDB -> the PKI key-amnesia NAK, on the primary channel.
    auto p = makeEncryptedToUs(/*channel=*/0, /*wantAck=*/true);
    uint8_t expectedHop = mockRoutingModule->getHopLimitForResponse(p);

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_PKI_UNKNOWN_PUBKEY, kRemoteNode, p.id, channels.getPrimaryIndex(), expectedHop,
                       /*ackWantsAck=*/false);
}

void test_pki_keyless_sender_record_gets_pki_unknown_pubkey_nak(void)
{
    // The sender is in the DB but we hold no key for it - same NAK as a fully unknown node.
    mockNodeDB->addNode(kRemoteNode, /*publicKeySize=*/0);
    auto p = makeEncryptedToUs(/*channel=*/0, /*wantAck=*/true);
    uint8_t expectedHop = mockRoutingModule->getHopLimitForResponse(p);

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_PKI_UNKNOWN_PUBKEY, kRemoteNode, p.id, channels.getPrimaryIndex(), expectedHop,
                       /*ackWantsAck=*/false);
}

void test_pki_known_key_sender_gets_no_channel_nak(void)
{
    // Discriminator: with the sender's key on hand an undecodable channel-0 want_ack packet is NOT a
    // key problem, so it falls through to the generic NO_CHANNEL NAK.
    mockNodeDB->addNode(kRemoteNode, /*publicKeySize=*/32);
    auto p = makeEncryptedToUs(/*channel=*/0, /*wantAck=*/true);
    uint8_t expectedHop = mockRoutingModule->getHopLimitForResponse(p);

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NO_CHANNEL, kRemoteNode, p.id, channels.getPrimaryIndex(), expectedHop,
                       /*ackWantsAck=*/false);
}

void test_unknown_channel_hash_gets_no_channel_nak(void)
{
    // Nonzero channel hash we cannot decode -> NO_CHANNEL on the primary channel (not the hash).
    auto p = makeEncryptedToUs(/*channel=*/0x5A, /*wantAck=*/true);
    uint8_t expectedHop = mockRoutingModule->getHopLimitForResponse(p);

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NO_CHANNEL, kRemoteNode, p.id, channels.getPrimaryIndex(), expectedHop,
                       /*ackWantsAck=*/false);
}

// ===========================================================================
// Group 3 - no want_ack, but we are the addressed next hop
// ===========================================================================

void test_next_hop_addressed_to_us_gets_zero_hop_ack(void)
{
    // We were the addressed next hop: a 0-hop ACK stops the relayer's retransmissions even though
    // the packet itself did not ask for an ACK.
    auto p = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/false);
    p.next_hop = 0x11; // our last byte
    p.hop_limit = 1;

    reliableShim->sniffForTest(&p, nullptr);

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kRemoteNode, p.id, 1, /*hopLimit=*/0, /*ackWantsAck=*/false);
}

void test_next_hop_with_hop_limit_zero_gets_no_ack(void)
{
    auto p = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/false);
    p.next_hop = 0x11;
    p.hop_limit = 0;

    reliableShim->sniffForTest(&p, nullptr);

    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
}

void test_next_hop_other_byte_gets_no_ack(void)
{
    auto p = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/false);
    p.next_hop = 0x22; // someone else's byte
    p.hop_limit = 1;

    reliableShim->sniffForTest(&p, nullptr);

    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
}

// ===========================================================================
// Group 4 - explicit ACK/NAK vs pending retransmissions, MQTT gate, route health
// ===========================================================================

void test_explicit_ack_stops_retransmissions_and_clears_route_failures(void)
{
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    reliableShim->noteRouteLearned(kRemoteNode, 0xAB, millis());
    reliableShim->noteRouteFailure(kRemoteNode);
    reliableShim->noteRouteFailure(kRemoteNode);
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());

    auto ack = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kRemoteNode, kLocalNode, 1);
    ack.decoded.request_id = original.id;
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.error_reason = meshtastic_Routing_Error_NONE;

    reliableShim->sniffForTest(&ack, &routing);

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    // The end-to-end ACK proves the route to its sender works -> noteRouteSuccess clears failures.
    RouteHealth *h = reliableShim->findRouteHealth(kRemoteNode);
    TEST_ASSERT_NOT_NULL(h);
    TEST_ASSERT_EQUAL_UINT8(0, h->consecutiveFailures);
}

void test_nak_stops_retransmissions_but_keeps_route_failures(void)
{
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    reliableShim->noteRouteLearned(kRemoteNode, 0xAB, millis());
    reliableShim->noteRouteFailure(kRemoteNode);
    reliableShim->noteRouteFailure(kRemoteNode);

    auto nak = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kRemoteNode, kLocalNode, 1);
    nak.decoded.request_id = original.id;
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.error_reason = meshtastic_Routing_Error_MAX_RETRANSMIT;

    reliableShim->sniffForTest(&nak, &routing);

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    // A NAK is not a delivery success: the failure count must survive.
    RouteHealth *h = reliableShim->findRouteHealth(kRemoteNode);
    TEST_ASSERT_NOT_NULL(h);
    TEST_ASSERT_EQUAL_UINT8(2, h->consecutiveFailures);
}

void test_pki_unknown_pubkey_nak_stops_retransmissions(void)
{
    // The remote lost our key: its PKI_UNKNOWN_PUBKEY NAK must still clear the pending record.
    // owner.public_key.size == 0 (setUp) keeps the NodeInfo re-send branch (a nodeInfoModule
    // dereference, null in this harness) out of the path.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    auto nak = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kRemoteNode, kLocalNode, 1);
    nak.decoded.request_id = original.id;
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.error_reason = meshtastic_Routing_Error_PKI_UNKNOWN_PUBKEY;

    reliableShim->sniffForTest(&nak, &routing);

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
}

void test_own_ack_echo_via_mqtt_keeps_retransmissions(void)
{
    // An implicit ACK that is our own traffic echoed back via MQTT must not stop LoRa retries.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    auto echo = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kLocalNode, kLocalNode, 1);
    echo.decoded.request_id = original.id;
    echo.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;

    reliableShim->sniffForTest(&echo, nullptr);

    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_TRUE(reliableShim->hasPending(kLocalNode, original.id));
}

void test_own_ack_echo_via_lora_stops_retransmissions(void)
{
    // Control for the MQTT gate: the identical from-us echo via LoRa does stop the retries.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    auto echo = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kLocalNode, kLocalNode, 1);
    echo.decoded.request_id = original.id;
    echo.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;

    reliableShim->sniffForTest(&echo, nullptr);

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
}

void test_remote_ack_via_mqtt_still_stops_retransmissions(void)
{
    // The gate is scoped to from-us echoes: a genuine end-to-end ACK arriving over MQTT counts.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    auto ack = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kRemoteNode, kLocalNode, 1);
    ack.decoded.request_id = original.id;
    ack.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.error_reason = meshtastic_Routing_Error_NONE;

    reliableShim->sniffForTest(&ack, &routing);

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
}

// ===========================================================================
// Group 4b - the ack proof verdict ackProofStatusFor() reports, which MeshService::handleFromRadio()
// stamps onto MeshPacket.ack_proof_status for the phone. VALID must mean "the node we addressed
// received it", so a proof minted by any other keyed peer reads ABSENT, never VALID. The verdict is
// keyed to the ack that carried it, so every other packet delivered to the phone reads ABSENT. The
// ingress clear is covered in test_packet_signing (C-group).
// ===========================================================================

#if !(MESHTASTIC_EXCLUDE_PKI)
struct TestIdentity {
    uint8_t pub[32];
    uint8_t priv[32];
};

static TestIdentity makeTestIdentity()
{
    TestIdentity id;
    crypto->generateKeyPair(id.pub, id.priv);
    return id;
}

static void actAs(const TestIdentity &id)
{
    uint8_t priv[32];
    memcpy(priv, id.priv, sizeof(priv));
    crypto->setDHPrivateKey(priv);
}

/** A success ack from `from` for `requestId`, carrying a proof `from` mints against `proofPeer`. */
static meshtastic_MeshPacket makeProvenAck(NodeNum from, PacketId requestId, const TestIdentity &author, const uint8_t *proofPeer)
{
    auto ack = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, from, kLocalNode, 1);
    ack.decoded.request_id = requestId;
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.which_variant = meshtastic_Routing_error_reason_tag;
    routing.error_reason = meshtastic_Routing_Error_NONE;
    ack.decoded.payload.size =
        pb_encode_to_bytes(ack.decoded.payload.bytes, sizeof(ack.decoded.payload.bytes), &meshtastic_Routing_msg, &routing);
    TEST_ASSERT_GREATER_THAN(0, ack.decoded.payload.size);
    actAs(author);
    TEST_ASSERT_TRUE(ackProofAttachWithKey(&ack, proofPeer));
    return ack;
}

static meshtastic_MeshPacket_AckProofStatus sniffAck(const meshtastic_MeshPacket &ack, const TestIdentity &local)
{
    actAs(local);
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.error_reason = meshtastic_Routing_Error_NONE;
    reliableShim->sniffForTest(&ack, &routing);
    return reliableShim->ackProofStatusFor(ack);
}

void test_ack_proof_from_the_addressed_node_reports_valid(void)
{
    const TestIdentity local = makeTestIdentity();
    const TestIdentity remote = makeTestIdentity();
    mockNodeDB->addNodeWithKey(kRemoteNode, remote.pub);
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    auto ack = makeProvenAck(kRemoteNode, original.id, remote, local.pub);

    TEST_ASSERT_EQUAL(meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_VALID, sniffAck(ack, local));
}

void test_ack_proof_that_fails_to_verify_reports_invalid(void)
{
    const TestIdentity local = makeTestIdentity();
    const TestIdentity remote = makeTestIdentity();
    const TestIdentity other = makeTestIdentity();
    mockNodeDB->addNodeWithKey(kRemoteNode, remote.pub);
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    // Minted under a secret the remote shares with someone else, so it cannot verify against ours.
    auto ack = makeProvenAck(kRemoteNode, original.id, remote, other.pub);

    TEST_ASSERT_EQUAL(meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_INVALID, sniffAck(ack, local));
}

void test_ack_proof_from_a_third_peer_reports_absent(void)
{
    const TestIdentity local = makeTestIdentity();
    const TestIdentity remote = makeTestIdentity();
    const TestIdentity third = makeTestIdentity();
    mockNodeDB->addNodeWithKey(kRemoteNode, remote.pub);
    mockNodeDB->addNodeWithKey(kThirdNode, third.pub);
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    // A proof that verifies under the third peer's own key, for a packet that went to the remote.
    auto ack = makeProvenAck(kThirdNode, original.id, third, local.pub);

    TEST_ASSERT_EQUAL(meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_ABSENT, sniffAck(ack, local));
}

void test_ack_proof_verdict_is_reported_only_for_its_own_ack(void)
{
    const TestIdentity local = makeTestIdentity();
    const TestIdentity remote = makeTestIdentity();
    mockNodeDB->addNodeWithKey(kRemoteNode, remote.pub);
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    auto ack = makeProvenAck(kRemoteNode, original.id, remote, local.pub);
    TEST_ASSERT_EQUAL(meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_VALID, sniffAck(ack, local));

    // Arrives claiming VALID; the phone must see ABSENT, because we reached no verdict for it.
    auto spoofed = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kRemoteNode, kLocalNode, 1);
    spoofed.ack_proof_status = meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_VALID;
    TEST_ASSERT_EQUAL(meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_ABSENT, reliableShim->ackProofStatusFor(spoofed));
}
#endif

// ===========================================================================
// Group 5 - implicit ACK for our own overheard DM through shouldFilterReceived. This is the
// pre-existing route (a decodable copy still in encrypted wire form reaches it); the #11502
// opaque short-circuit is exercised separately in Group 5b.
// ===========================================================================

void test_overheard_own_dm_rebroadcast_mints_implicit_ack(void)
{
    // The implicit ACK is minted from the header alone (from/id), so this route must work on a
    // still-encrypted packet, and the LoRa copy stops the retransmissions.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    meshtastic_MeshPacket overheard = meshtastic_MeshPacket_init_zero;
    overheard.from = kLocalNode;
    overheard.to = kRemoteNode;
    overheard.id = original.id;
    overheard.hop_start = 3;
    overheard.hop_limit = 2;
    overheard.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    overheard.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    overheard.encrypted.size = 32;
    overheard.relay_node = 0x99;
    overheard.has_rx_rssi = true;
    overheard.rx_rssi = -87;
    overheard.rx_snr = 6.25f;

    reliableShim->filterForTest(&overheard);

    // ACK is addressed to us (so it reaches the phone) on the pending copy's channel.
    expectSingleAckNak(meshtastic_Routing_Error_NONE, kLocalNode, original.id, 1, /*hopLimit=*/0, /*ackWantsAck=*/false);
    // The overheard copy is the relay source, so the phone learns who relayed and at what quality.
    expectRelaySource(0x99, -87, 6.25f);
    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
}

void test_overheard_own_dm_via_mqtt_acks_but_keeps_retransmissions(void)
{
    // The MQTT copy still surfaces "Delivered to mesh" but must not cancel the LoRa retries.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    meshtastic_MeshPacket overheard = meshtastic_MeshPacket_init_zero;
    overheard.from = kLocalNode;
    overheard.to = kRemoteNode;
    overheard.id = original.id;
    overheard.hop_start = 3;
    overheard.hop_limit = 2;
    overheard.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;
    overheard.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    overheard.encrypted.size = 32;

    reliableShim->filterForTest(&overheard);

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kLocalNode, original.id, 1, /*hopLimit=*/0, /*ackWantsAck=*/false);
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
}

void test_overheard_foreign_packet_mints_no_implicit_ack(void)
{
    // Someone else's traffic must never mint an ACK, even with a colliding packet id.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    meshtastic_MeshPacket foreign = meshtastic_MeshPacket_init_zero;
    foreign.from = kRemoteNode;
    foreign.to = kThirdNode;
    foreign.id = original.id;
    foreign.hop_start = 3;
    foreign.hop_limit = 2;
    foreign.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    foreign.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    foreign.encrypted.size = 32;

    reliableShim->filterForTest(&foreign);

    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
}

// ===========================================================================
// Group 5b - the real #11502 wiring: an overheard own DM under a channel hash we cannot decode
// (a PKI DM we sent) is OPAQUE_RELAY_ONLY in Router::perhapsHandleReceived and returns BEFORE
// shouldFilterReceived; the fix is the isFromUs branch there. Driven through the public ingress
// queue (enqueueReceivedMessage + runOnce), so deleting that branch fails these tests.
// ===========================================================================

// An encrypted copy of our own DM under an unknown channel hash: not to us (no PKI attempt), no
// hash match -> DECODE_OPAQUE -> OPAQUE_RELAY_ONLY. hop_limit > 0 so the opaque relay does not
// short-circuit before the ACK branch.
static meshtastic_MeshPacket makeOpaqueOwnOverheard(PacketId id, meshtastic_MeshPacket_TransportMechanism transport)
{
    meshtastic_MeshPacket p = meshtastic_MeshPacket_init_zero;
    p.from = kLocalNode;
    p.to = kRemoteNode;
    p.id = id;
    p.channel = 0x5A;
    p.hop_start = 3;
    p.hop_limit = 2;
    p.transport_mechanism = transport;
    p.which_payload_variant = meshtastic_MeshPacket_encrypted_tag;
    p.encrypted.size = 32;
    memset(p.encrypted.bytes, 0xC3, p.encrypted.size);
    p.relay_node = 0x4D;
    p.has_rx_rssi = true;
    p.rx_rssi = -112;
    p.rx_snr = -3.5f;
    return p;
}

static void ingressOverheard(const meshtastic_MeshPacket &p)
{
    meshtastic_MeshPacket *copy = packetPool.allocCopy(p);
    TEST_ASSERT_NOT_NULL(copy);
    reliableShim->enqueueReceivedMessage(copy);
    reliableShim->runOnce();
}

void test_ingress_opaque_own_dm_lora_mints_implicit_ack_and_stops_retries(void)
{
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    ingressOverheard(makeOpaqueOwnOverheard(original.id, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA));

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kLocalNode, original.id, 1, /*hopLimit=*/0, /*ackWantsAck=*/false);
    // Relay attribution survives the opaque short-circuit too: the header fields are all it needs.
    expectRelaySource(0x4D, -112, -3.5f);
    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
}

void test_ingress_opaque_own_dm_mqtt_acks_but_keeps_retries(void)
{
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    ingressOverheard(makeOpaqueOwnOverheard(original.id, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT));

    expectSingleAckNak(meshtastic_Routing_Error_NONE, kLocalNode, original.id, 1, /*hopLimit=*/0, /*ackWantsAck=*/false);
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
}

void test_ingress_opaque_foreign_packet_mints_no_implicit_ack(void)
{
    // The isFromUs guard on the opaque branch: someone else's opaque traffic with a colliding id
    // is relayed but never ACKed.
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(original, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);

    auto foreign = makeOpaqueOwnOverheard(original.id, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA);
    foreign.from = kRemoteNode;
    foreign.to = kThirdNode;
    ingressOverheard(foreign);

    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
}

// ===========================================================================
// Group 6 - pending-timer airtime extension in send() and shouldFilterReceived()
// ===========================================================================

void test_send_extends_other_pending_deadlines_not_own(void)
{
    // While we transmit packet B we cannot hear an (implicit) ACK for pending A, so A's deadline
    // must move out by B's airtime. B's own fresh record must not be self-extended.
    radio->packetTimeMsec = 50000; // dwarfs any real time elapsed inside the test

    auto a = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(a, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    uint32_t aBefore = reliableShim->pendingNextTx(kLocalNode, a.id);

    auto b = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, NODENUM_BROADCAST, 0, /*wantAck=*/true);
    auto *allocated = packetPool.allocCopy(b);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));

    TEST_ASSERT_EQUAL_UINT32(2, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(aBefore + 50000, reliableShim->pendingNextTx(kLocalNode, a.id));

    // B's deadline is millis-at-set + getRetransmissionMsec(B); a self-extension would push it a
    // further 50s out, past anything the wall clock could account for.
    uint32_t bTx = reliableShim->pendingNextTx(kLocalNode, b.id);
    uint32_t retrans = radio->getRetransmissionMsec(reliableShim->pendingPacket(kLocalNode, b.id));
    // Via Throttle rather than a bare millis() compare, per the house deadline rule.
    TEST_ASSERT_TRUE_MESSAGE(Throttle::deadlinePassed(bTx - retrans), "own record must not be extended by its own send");
}

void test_receive_extends_all_pending_deadlines(void)
{
    // While receiving any packet we cannot hear an ACK either: every pending deadline moves out by
    // the received packet's airtime.
    radio->packetTimeMsec = 40000;

    auto a = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(a, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    auto b = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kThirdNode, 1, /*wantAck=*/true);
    reliableShim->seedRetry(b, NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    uint32_t aBefore = reliableShim->pendingNextTx(kLocalNode, a.id);
    uint32_t bBefore = reliableShim->pendingNextTx(kLocalNode, b.id);

    auto inbound = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1, /*wantAck=*/false);
    reliableShim->filterForTest(&inbound);

    TEST_ASSERT_EQUAL_UINT32(aBefore + 40000, reliableShim->pendingNextTx(kLocalNode, a.id));
    TEST_ASSERT_EQUAL_UINT32(bBefore + 40000, reliableShim->pendingNextTx(kLocalNode, b.id));
}

// Regression seam for the real queue/hardware boundary: leave the initial packet queued and advance
// every old retry deadline without starting or completing a transmission. Waiting for hardware must
// not consume ACK retries, emit MAX_RETRANSMIT, or add retry copies behind the one admitted packet.
void test_reliable_queue_wait_does_not_consume_ack_retry_budget(void)
{
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    const uint32_t oldRetryInterval = radio->getRetransmissionMsec(&original);
    TEST_ASSERT_LESS_THAN_UINT32(NextHopRouter::TX_QUEUE_WAIT_MSEC,
                                 (oldRetryInterval + 1) * NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, radio->queuedCount());
    TEST_ASSERT_TRUE(reliableShim->pendingRadioCandidateIsClear(kLocalNode, original.id));

    for (uint8_t i = 0; i < NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS; ++i) {
        // Move beyond each old ACK retry deadline while staying far below the planned queue wait
        // timeout. A real queued packet has not reached a TX boundary during this interval.
        Time::advanceTestMillis(oldRetryInterval + 1);
        reliableShim->runDueRetries();
    }

    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_UINT32(1, radio->queuedCount());
    TEST_ASSERT_TRUE(radio->startTransmissionForTest());
    TEST_ASSERT_TRUE(radio->completeTransmissionForTest());

    // Completion, rather than queue admission, starts ACK waiting. The first valid ACK then
    // retires the pending record without any retry copy having been admitted.
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(0, radio->queuedCount());

    auto ack = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kRemoteNode, kLocalNode, 1);
    ack.decoded.request_id = original.id;
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.error_reason = meshtastic_Routing_Error_NONE;
    reliableShim->sniffForTest(&ack, &routing);
    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());

    radio->reset();
    Time::useRealClock();
}

void test_reliable_ack_budget_starts_after_each_successful_tx(void)
{
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    const uint32_t retryInterval = radio->getRetransmissionMsec(&original);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));

    // The initial send crosses the hardware boundary successfully, but no peer ACK arrives.
    TEST_ASSERT_TRUE(radio->startTransmissionForTest());
    TEST_ASSERT_TRUE(radio->completeTransmissionForTest());
    reliableShim->runDueRetries();
    TEST_ASSERT_TRUE(reliableShim->pendingWaitsForAck(kLocalNode, original.id));
    TEST_ASSERT_EQUAL_UINT8(NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS - 1,
                            reliableShim->pendingRetries(kLocalNode, original.id));

    // Every retry allowance is earned by a completed TX. A queued retry alone must not consume it.
    for (uint8_t attempt = 1; attempt < NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS; ++attempt) {
        Time::advanceTestMillis(retryInterval + 1);
        reliableShim->runDueRetries();
        TEST_ASSERT_EQUAL_UINT32(1, radio->queuedCount());
        TEST_ASSERT_TRUE(radio->startTransmissionForTest());
        TEST_ASSERT_TRUE(radio->completeTransmissionForTest());
        reliableShim->runDueRetries();
        TEST_ASSERT_EQUAL_UINT8(NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS - 1 - attempt,
                                reliableShim->pendingRetries(kLocalNode, original.id));
    }

    Time::advanceTestMillis(retryInterval + 1);
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_INT(meshtastic_Routing_Error_MAX_RETRANSMIT, std::get<0>(mockRoutingModule->ackNaks.front()));
    radio->reset();
    Time::useRealClock();
}

void test_reliable_queue_timeout_is_distinct_from_ack_exhaustion(void)
{
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    const uint32_t oldRetryInterval = radio->getRetransmissionMsec(&original);
    TEST_ASSERT_LESS_THAN_UINT32(NextHopRouter::TX_QUEUE_WAIT_MSEC,
                                 oldRetryInterval * NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));

    // Several old retry intervals pass, then the distinct bounded queue wait expires while the
    // first physical copy is still queued.
    Time::advanceTestMillis(oldRetryInterval * 5);
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());

    Time::advanceTestMillis(NextHopRouter::TX_QUEUE_WAIT_MSEC + 1);
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_INT(meshtastic_Routing_Error_TIMEOUT, std::get<0>(mockRoutingModule->ackNaks.front()));
    radio->reset();
    Time::useRealClock();
}

void test_reliable_tx_failures_have_separate_bounded_retry_budget(void)
{
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));
    const uint8_t ackRetries = reliableShim->pendingRetries(kLocalNode, original.id);

    // A failed physical attempt gets its own bounded retry budget. It must not spend the ACK
    // allowance, and the third physical failure reports NO_INTERFACE rather than MAX_RETRANSMIT.
    for (uint8_t failure = 0; failure < NextHopRouter::MAX_TX_FAILURES; ++failure) {
        TEST_ASSERT_TRUE(radio->startTransmissionForTest());
        TEST_ASSERT_TRUE(radio->completeTransmissionForTest(RadioInterface::TxState::Failed));
        reliableShim->runDueRetries();

        if (failure + 1 < NextHopRouter::MAX_TX_FAILURES) {
            TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
            TEST_ASSERT_EQUAL_UINT8(ackRetries, reliableShim->pendingRetries(kLocalNode, original.id));
            Time::advanceTestMillis(NextHopRouter::TX_FAILURE_BACKOFF_MSEC);
            reliableShim->runDueRetries();
            TEST_ASSERT_EQUAL_UINT32(1, radio->queuedCount());
        }
    }

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_INT(meshtastic_Routing_Error_NO_INTERFACE, std::get<0>(mockRoutingModule->ackNaks.front()));
    radio->reset();
    Time::useRealClock();
}

void test_failed_tx_after_queue_deadline_uses_failure_budget(void)
{
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));

    // A driver may begin a packet after its queue deadline has elapsed. Once TX has actually
    // started, a failed attempt belongs to the physical-failure budget, not the queue-timeout path.
    Time::advanceTestMillis(NextHopRouter::TX_QUEUE_WAIT_MSEC + 1);
    TEST_ASSERT_TRUE(radio->startTransmissionForTest());
    TEST_ASSERT_TRUE(radio->completeTransmissionForTest(RadioInterface::TxState::Failed));
    reliableShim->runDueRetries();

    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_UINT8(NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS - 1,
                            reliableShim->pendingRetries(kLocalNode, original.id));

    reliableShim->clearPendingForTest();
    radio->reset();
    Time::useRealClock();
}

void test_rx_airtime_extends_deadline_after_tx_completion_is_observed(void)
{
    radio->deferTransmissions = true;
    radio->packetTimeMsec = 40000;
    Time::setTestMillis(1);

    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));
    TEST_ASSERT_TRUE(radio->startTransmissionForTest());
    TEST_ASSERT_TRUE(radio->completeTransmissionForTest());
    const uint32_t completion = Time::getMillis();
    const uint32_t retryInterval = radio->getRetransmissionMsec(reliableShim->pendingPacket(kLocalNode, original.id));

    // RX can arrive after TX_DONE but before the retry task observes that completion. The airtime
    // extension must still be attached to the new ACK deadline in that ordering.
    auto inbound = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kRemoteNode, kLocalNode, 1);
    reliableShim->filterForTest(&inbound);
    TEST_ASSERT_EQUAL_UINT32(completion + retryInterval + radio->packetTimeMsec,
                             reliableShim->pendingNextTx(kLocalNode, original.id));
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(completion + retryInterval + radio->packetTimeMsec,
                             reliableShim->pendingNextTx(kLocalNode, original.id));

    reliableShim->clearPendingForTest();
    radio->reset();
    Time::useRealClock();
}

void test_unpaced_reliable_burst_waits_in_queue_without_spending_budgets(void)
{
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    std::vector<meshtastic_MeshPacket> originals;
    originals.reserve(MAX_TX_QUEUE);
    uint32_t oldRetryInterval = 0;
    for (size_t i = 0; i < MAX_TX_QUEUE; ++i) {
        auto packet = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
        packet.decoded.payload.size = 100;
        memset(packet.decoded.payload.bytes, 'A' + (int)(i % 26), packet.decoded.payload.size);
        oldRetryInterval = radio->getRetransmissionMsec(&packet);
        originals.push_back(packet);

        auto *allocated = packetPool.allocCopy(packet);
        TEST_ASSERT_NOT_NULL(allocated);
        TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));
    }

    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());
    for (const auto &packet : originals)
        TEST_ASSERT_TRUE(reliableShim->pendingRadioCandidateIsClear(kLocalNode, packet.id));

    TEST_ASSERT_LESS_THAN_UINT32(NextHopRouter::TX_QUEUE_WAIT_MSEC,
                                 oldRetryInterval * NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    Time::advanceTestMillis(oldRetryInterval * 5);
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    for (const auto &packet : originals)
        TEST_ASSERT_EQUAL_UINT8(NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS - 1,
                                reliableShim->pendingRetries(kLocalNode, packet.id));

    // Now let every admitted packet cross the controlled hardware boundary once. Each completion
    // starts its ACK wait; no retry is due because virtual time stays fixed while draining.
    for (size_t i = 0; i < MAX_TX_QUEUE; ++i) {
        TEST_ASSERT_TRUE(radio->startTransmissionForTest());
        const PacketId id = radio->sentPackets.back().id;
        TEST_ASSERT_TRUE(radio->completeTransmissionForTest());
        reliableShim->runDueRetries();
        TEST_ASSERT_TRUE(reliableShim->hasPending(kLocalNode, id));
        TEST_ASSERT_TRUE(reliableShim->pendingWaitsForAck(kLocalNode, id));
    }
    TEST_ASSERT_EQUAL_UINT32(0, radio->queuedCount());
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());

    reliableShim->clearPendingForTest();
    radio->reset();
    Time::useRealClock();
}

#if !(MESHTASTIC_EXCLUDE_PKI)
// Keep the burst regression tied to the real proof verifier as well as the queue lifecycle. This
// is still a router test: the proof is minted by the configured peer identity, not by a hardware
// receive/decode path, so it does not claim two-node RF delivery.
void test_unpaced_reliable_burst_accepts_authenticated_acks(void)
{
    const TestIdentity local = makeTestIdentity();
    const TestIdentity remote = makeTestIdentity();
    mockNodeDB->addNodeWithKey(kRemoteNode, remote.pub);
    mockNodeDB->addNodeWithKey(kLocalNode, local.pub);

    config.security.private_key.size = sizeof(local.priv);
    memcpy(config.security.private_key.bytes, local.priv, sizeof(local.priv));
    owner.public_key.size = sizeof(local.pub);
    memcpy(owner.public_key.bytes, local.pub, sizeof(local.pub));
    actAs(local);
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    std::array<meshtastic_MeshPacket, MAX_TX_QUEUE> originals;
    uint32_t oldRetryInterval = 0;
    for (size_t i = 0; i < MAX_TX_QUEUE; ++i) {
        auto packet = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 0, /*wantAck=*/true);
        packet.decoded.payload.size = 100;
        memset(packet.decoded.payload.bytes, 'a' + (int)(i % 26), packet.decoded.payload.size);
        oldRetryInterval = radio->getRetransmissionMsec(&packet);
        originals[i] = packet;

        auto *allocated = packetPool.allocCopy(packet);
        TEST_ASSERT_NOT_NULL(allocated);
        TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));
    }

    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());

    TEST_ASSERT_LESS_THAN_UINT32(NextHopRouter::TX_QUEUE_WAIT_MSEC,
                                 oldRetryInterval * NextHopRouter::NUM_RELIABLE_UNICAST_ATTEMPTS);
    Time::advanceTestMillis(oldRetryInterval * 5);
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());

    for (const auto &original : originals) {
        TEST_ASSERT_TRUE(radio->startTransmissionForTest());
        TEST_ASSERT_EQUAL_HEX32(original.id, radio->sentPackets.back().id);
        TEST_ASSERT_TRUE(radio->completeTransmissionForTest());
        reliableShim->runDueRetries();

        // Exercise the actual PKI ciphertext as the receiving node before evaluating its
        // authenticated receipt. The queue test's sender packet remains a captured wire frame.
        auto receipt = radio->sentPackets.back();
        const NodeNum sender = myNodeInfo.my_node_num;
        myNodeInfo.my_node_num = kRemoteNode;
        actAs(remote);
        TEST_ASSERT_EQUAL(DecodeState::DECODE_SUCCESS, perhapsDecode(&receipt));
        TEST_ASSERT_TRUE(receipt.pki_encrypted);
        TEST_ASSERT_EQUAL_UINT32(original.id, receipt.id);
        TEST_ASSERT_EQUAL_HEX32(kLocalNode, receipt.from);
        TEST_ASSERT_EQUAL_HEX32(kRemoteNode, receipt.to);
        TEST_ASSERT_EQUAL(meshtastic_PortNum_TEXT_MESSAGE_APP, receipt.decoded.portnum);
        TEST_ASSERT_EQUAL_UINT32(original.decoded.payload.size, receipt.decoded.payload.size);
        TEST_ASSERT_EQUAL_MEMORY(original.decoded.payload.bytes, receipt.decoded.payload.bytes, original.decoded.payload.size);
        myNodeInfo.my_node_num = sender;
        actAs(local);

        auto ack = makeProvenAck(kRemoteNode, original.id, remote, local.pub);
        TEST_ASSERT_EQUAL(meshtastic_MeshPacket_AckProofStatus_ACK_PROOF_VALID, sniffAck(ack, local));
    }

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(0, radio->queuedCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    radio->reset();
    Time::useRealClock();
}
#endif

static meshtastic_MeshPacket makeQueueFiller(PacketId id)
{
    auto filler = makeDecodedPacket(meshtastic_PortNum_TELEMETRY_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/false);
    filler.id = id;
    filler.priority = meshtastic_MeshPacket_Priority_HIGH;
    return filler;
}

void test_queue_eviction_and_rejection_do_not_spend_ack_budget(void)
{
    radio->deferTransmissions = true;
    Time::setTestMillis(1);

    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    original.priority = meshtastic_MeshPacket_Priority_DEFAULT;
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));
    const uint8_t ackRetries = reliableShim->pendingRetries(kLocalNode, original.id);

    // Fill the real queue with higher-priority traffic, leaving the reliable packet as the victim
    // when a routing ACK packet arrives. The victim is then followed by an explicit rejection when
    // its lower-priority retry cannot displace the full queue.
    for (uint8_t i = 0; i < MAX_TX_QUEUE - 1; ++i) {
        auto filler = makeQueueFiller(0x61000000u + i);
        auto *copy = packetPool.allocCopy(filler);
        TEST_ASSERT_NOT_NULL(copy);
        TEST_ASSERT_EQUAL_INT(ERRNO_OK, radio->send(copy));
    }
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());

    auto queueAck = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/false);
    auto *ackCopy = packetPool.allocCopy(queueAck);
    TEST_ASSERT_NOT_NULL(ackCopy);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(ackCopy));
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT8(ackRetries, reliableShim->pendingRetries(kLocalNode, original.id));
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());

    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT8(ackRetries, reliableShim->pendingRetries(kLocalNode, original.id));
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());

    // The retry copy is now due, but the full queue contains only higher-priority packets. The
    // attempted re-admission is an explicit rejection and still must not spend an ACK retry.
    Time::advanceTestMillis(NextHopRouter::TX_FAILURE_BACKOFF_MSEC);
    reliableShim->runDueRetries();
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT8(ackRetries, reliableShim->pendingRetries(kLocalNode, original.id));
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    TEST_ASSERT_EQUAL_UINT32(MAX_TX_QUEUE, radio->queuedCount());

    reliableShim->clearPendingForTest();
    radio->reset();
    Time::useRealClock();
}

void test_same_id_routing_packet_cannot_replace_reliable_pending_packet(void)
{
    radio->deferTransmissions = true;
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));

    auto collision = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/false);
    collision.id = original.id;
    auto *collisionCopy = packetPool.allocCopy(collision);
    TEST_ASSERT_NOT_NULL(collisionCopy);
    TEST_ASSERT_EQUAL_INT(meshtastic_Routing_Error_BAD_REQUEST, reliableShim->send(collisionCopy));
    TEST_ASSERT_EQUAL_UINT32(1, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, radio->queuedCount());

    reliableShim->clearPendingForTest();
    radio->reset();
}

void test_mqtt_ack_retains_first_queued_copy_and_blocks_new_generation(void)
{
    radio->deferTransmissions = true;
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));

    auto mqttAck = makeDecodedPacket(meshtastic_PortNum_ROUTING_APP, kRemoteNode, kLocalNode, 1);
    mqttAck.decoded.request_id = original.id;
    mqttAck.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;
    meshtastic_Routing routing = meshtastic_Routing_init_zero;
    routing.error_reason = meshtastic_Routing_Error_NONE;
    reliableShim->sniffForTest(&mqttAck, &routing);

    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(1, radio->queuedCount());

    auto replacement = original;
    replacement.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    auto *replacementCopy = packetPool.allocCopy(replacement);
    TEST_ASSERT_NOT_NULL(replacementCopy);
    TEST_ASSERT_EQUAL_INT(meshtastic_Routing_Error_BAD_REQUEST, reliableShim->send(replacementCopy));
    TEST_ASSERT_EQUAL_UINT32(1, radio->queuedCount());

    TEST_ASSERT_TRUE(radio->startTransmissionForTest());
    TEST_ASSERT_TRUE(radio->completeTransmissionForTest());
    radio->reset();
}

void test_explicit_queue_cancel_retires_without_delivery_nak(void)
{
    radio->deferTransmissions = true;
    auto original = makeDecodedPacket(meshtastic_PortNum_TEXT_MESSAGE_APP, kLocalNode, kRemoteNode, 1, /*wantAck=*/true);
    auto *allocated = packetPool.allocCopy(original);
    TEST_ASSERT_NOT_NULL(allocated);
    TEST_ASSERT_EQUAL_INT(ERRNO_OK, reliableShim->send(allocated));

    TEST_ASSERT_TRUE(reliableShim->stopForTest(kLocalNode, original.id));
    TEST_ASSERT_EQUAL_UINT32(0, reliableShim->pendingCount());
    TEST_ASSERT_EQUAL_UINT32(0, radio->queuedCount());
    TEST_ASSERT_EQUAL_UINT32(0, mockRoutingModule->ackNaks.size());
    radio->reset();
}

// ===========================================================================

void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();

    airTimeFixture = std::make_unique<ScopedAirTimeFixture>();
    mockNodeDB = new MockNodeDB();
    nodeDB = mockNodeDB;
    reliableShim = new ReliableRouterTestShim();

    auto capture = std::make_unique<TimedCaptureRadio>();
    radio = capture.get();
    reliableShim->addInterface(std::move(capture));

    mockRoutingModule = new MockRoutingModule();
    routingModule = mockRoutingModule;

    printf("\n=== want_ack ACK variants ===\n");
    RUN_TEST(test_text_dm_want_ack_gets_want_ack_ack);
    RUN_TEST(test_text_reply_still_gets_want_ack_ack);
    RUN_TEST(test_nontext_dm_want_ack_gets_plain_ack);
    RUN_TEST(test_response_heard_directly_gets_zero_hop_ack);
    RUN_TEST(test_response_relayed_gets_no_ack);
    RUN_TEST(test_response_relayed_via_next_hop_gets_zero_hop_ack);
    RUN_TEST(test_broadcast_want_ack_gets_no_ack);

    printf("\n=== undecodable want_ack NAKs ===\n");
    RUN_TEST(test_pki_unknown_sender_gets_pki_unknown_pubkey_nak);
    RUN_TEST(test_pki_keyless_sender_record_gets_pki_unknown_pubkey_nak);
    RUN_TEST(test_pki_known_key_sender_gets_no_channel_nak);
    RUN_TEST(test_unknown_channel_hash_gets_no_channel_nak);

    printf("\n=== next-hop 0-hop ACK without want_ack ===\n");
    RUN_TEST(test_next_hop_addressed_to_us_gets_zero_hop_ack);
    RUN_TEST(test_next_hop_with_hop_limit_zero_gets_no_ack);
    RUN_TEST(test_next_hop_other_byte_gets_no_ack);

    printf("\n=== ACK/NAK vs pending retransmissions ===\n");
    RUN_TEST(test_explicit_ack_stops_retransmissions_and_clears_route_failures);
    RUN_TEST(test_nak_stops_retransmissions_but_keeps_route_failures);
    RUN_TEST(test_pki_unknown_pubkey_nak_stops_retransmissions);
    RUN_TEST(test_own_ack_echo_via_mqtt_keeps_retransmissions);
    RUN_TEST(test_own_ack_echo_via_lora_stops_retransmissions);
    RUN_TEST(test_remote_ack_via_mqtt_still_stops_retransmissions);

#if !(MESHTASTIC_EXCLUDE_PKI)
    printf("\n=== ack proof verdict reported to the phone ===\n");
    RUN_TEST(test_ack_proof_from_the_addressed_node_reports_valid);
    RUN_TEST(test_ack_proof_that_fails_to_verify_reports_invalid);
    RUN_TEST(test_ack_proof_from_a_third_peer_reports_absent);
    RUN_TEST(test_ack_proof_verdict_is_reported_only_for_its_own_ack);
#endif

    printf("\n=== implicit ACK for our own overheard DM ===\n");
    RUN_TEST(test_overheard_own_dm_rebroadcast_mints_implicit_ack);
    RUN_TEST(test_overheard_own_dm_via_mqtt_acks_but_keeps_retransmissions);
    RUN_TEST(test_overheard_foreign_packet_mints_no_implicit_ack);

    printf("\n=== implicit ACK through the opaque ingress short-circuit (#11502) ===\n");
    RUN_TEST(test_ingress_opaque_own_dm_lora_mints_implicit_ack_and_stops_retries);
    RUN_TEST(test_ingress_opaque_own_dm_mqtt_acks_but_keeps_retries);
    RUN_TEST(test_ingress_opaque_foreign_packet_mints_no_implicit_ack);

    printf("\n=== pending-timer airtime extension ===\n");
    RUN_TEST(test_send_extends_other_pending_deadlines_not_own);
    RUN_TEST(test_receive_extends_all_pending_deadlines);

    printf("\n=== queued reliable send lifecycle ===\n");
    RUN_TEST(test_reliable_queue_wait_does_not_consume_ack_retry_budget);
    RUN_TEST(test_reliable_ack_budget_starts_after_each_successful_tx);
    RUN_TEST(test_reliable_queue_timeout_is_distinct_from_ack_exhaustion);
    RUN_TEST(test_reliable_tx_failures_have_separate_bounded_retry_budget);
    RUN_TEST(test_failed_tx_after_queue_deadline_uses_failure_budget);
    RUN_TEST(test_rx_airtime_extends_deadline_after_tx_completion_is_observed);
    RUN_TEST(test_unpaced_reliable_burst_waits_in_queue_without_spending_budgets);
#if !(MESHTASTIC_EXCLUDE_PKI)
    RUN_TEST(test_unpaced_reliable_burst_accepts_authenticated_acks);
#endif
    RUN_TEST(test_queue_eviction_and_rejection_do_not_spend_ack_budget);
    RUN_TEST(test_same_id_routing_packet_cannot_replace_reliable_pending_packet);
    RUN_TEST(test_mqtt_ack_retains_first_queued_copy_and_blocks_new_generation);
    RUN_TEST(test_explicit_queue_cancel_retires_without_delivery_nak);

    int result = UNITY_END();
    airTimeFixture.reset();
    exit(result);
}

void loop() {}
